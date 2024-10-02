from typing import Optional, Union

from django.apps import apps
from django.db.models import F
from django.utils import timezone
from django_request_cache import cache_for_request

from kobo.apps.organizations.models import Organization
from kobo.apps.organizations.types import UsageType
from kobo.apps.stripe.constants import USAGE_LIMIT_MAP
from kobo.apps.stripe.utils import get_organization_plan_limit
from kpi.utils.django_orm_helper import IncrementValue
from kpi.utils.usage_calculator import ServiceUsageCalculator


def update_nlp_counter(
    service: str,
    amount: int,
    user_id: int,
    asset_id: Optional[int] = None,
    counter_id: Optional[int] = None,
):
    """
    Update the NLP ASR and MT tracker for various services
        Params:
            service (str): Service tracker to be updated, provider_service_type
                for example:
                    google_asr_seconds
            amount (int): units used. It could be seconds or characters depending
                on the service
            user_id (int): id of the asset owner
            asset_id (int) or None: Primary key for Asset Model
            counter_id (int) or None: Primary key for NLPUsageCounter instance
    """
    # Avoid circular import
    NLPUsageCounter = apps.get_model('trackers', 'NLPUsageCounter')  # noqa
    organization = Organization.get_from_user_id(user_id)

    if not counter_id:
        date = timezone.now()
        criteria = dict(
            date=date.date(),
            user_id=user_id,
            asset_id=asset_id,
        )

        # Ensure the counter for the date exists first
        counter, _ = NLPUsageCounter.objects.get_or_create(**criteria)
        counter_id = counter.pk

    # Update the total counters by the usage amount to keep them current
    kwargs = {}
    if service.endswith('asr_seconds'):
        kwargs['total_asr_seconds'] = F('total_asr_seconds') + amount
        if asset_id is not None and organization is not None:
            handle_usage_increment(organization, 'seconds', amount)
    if service.endswith('mt_characters'):
        kwargs['total_mt_characters'] = F('total_mt_characters') + amount
        if asset_id is not None and organization is not None:
            handle_usage_increment(organization, 'character', amount)

    NLPUsageCounter.objects.filter(pk=counter_id).update(
        counters=IncrementValue('counters', keyname=service, increment=amount),
        **kwargs,
    )


@cache_for_request
def get_organization_usage(organization: Organization, usage_type: UsageType) -> int:
    """
    Get the used amount for a given organization and usage type
    """
    usage_calc = ServiceUsageCalculator(
        organization.owner.organization_user.user, organization
    )
    usage_calc._clear_cache()  # Do not use cached values
    usage = usage_calc.get_nlp_usage_by_type(USAGE_LIMIT_MAP[usage_type])

    return usage


def get_organization_remaining_usage(
    organization: Organization, usage_type: UsageType
) -> Union[int, None]:
    """
    Get the organization remaining usage count for a given limit type
    """
    PlanAddOn = apps.get_model('stripe', 'PlanAddOn')  # noqa

    plan_limit = get_organization_plan_limit(organization, usage_type)
    if plan_limit is None:
        plan_limit = 0
    usage = get_organization_usage(organization, usage_type)
    addon_limit, addon_remaining = PlanAddOn.get_organization_totals(
        organization,
        usage_type,
    )
    remaining = addon_limit + plan_limit - usage

    return remaining


def handle_usage_increment(
    organization: Organization, usage_type: UsageType, amount: int
):
    """
    Increment the given usage type for this organization by the given amount
    """
    plan_limit = get_organization_plan_limit(organization, usage_type)
    current_usage = get_organization_usage(organization, usage_type)
    if current_usage is None:
        current_usage = 0
    new_total_usage = current_usage + amount
    if new_total_usage > plan_limit:
        increment = (
            amount if current_usage >= plan_limit else new_total_usage - plan_limit
        )
        PlanAddOn.increment_add_ons_for_organization(
            organization.id, usage_type, increment
        )
