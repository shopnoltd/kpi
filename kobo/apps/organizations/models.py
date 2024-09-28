from functools import partial
from typing import Union

from django.conf import settings
from django.db import models
from django.db.models import F
from django.utils import timezone
from django_request_cache import cache_for_request

if settings.STRIPE_ENABLED:
   from djstripe.models import Customer, Subscription
   from kobo.apps.stripe.constants import ACTIVE_STRIPE_STATUSES, ORGANIZATION_USAGE_MAX_CACHE_AGE

from organizations.abstract import (
    AbstractOrganization,
    AbstractOrganizationInvitation,
    AbstractOrganizationOwner,
    AbstractOrganizationUser,
)
from organizations.utils import create_organization as create_organization_base

from kpi.fields import KpiUidField


class Organization(AbstractOrganization):
    id = KpiUidField(uid_prefix='org', primary_key=True)

    @property
    def email(self):
        """
        As organization is our customer model for Stripe, Stripe requires that
        it has an email address attribute
        """
        return self.owner.organization_user.user.email

    @cache_for_request
    def active_subscription_billing_details(self):
        """
        Retrieve the billing dates, interval, and product/price metadata for the organization's newest subscription
        Returns None if Stripe is not enabled
        The status types that are considered 'active' are determined by ACTIVE_STRIPE_STATUSES
        """
        # Only check for subscriptions if Stripe is enabled
        if settings.STRIPE_ENABLED:
            return Organization.objects.prefetch_related('djstripe_customers').filter(
                    djstripe_customers__subscriptions__status__in=ACTIVE_STRIPE_STATUSES,
                    djstripe_customers__subscriber=self.id,
                ).order_by(
                    '-djstripe_customers__subscriptions__start_date'
                ).values(
                    billing_cycle_anchor=F('djstripe_customers__subscriptions__billing_cycle_anchor'),
                    current_period_start=F('djstripe_customers__subscriptions__current_period_start'),
                    current_period_end=F('djstripe_customers__subscriptions__current_period_end'),
                    recurring_interval=F('djstripe_customers__subscriptions__items__price__recurring__interval'),
                    product_metadata=F('djstripe_customers__subscriptions__items__price__product__metadata'),
                    price_metadata=F('djstripe_customers__subscriptions__items__price__metadata')
                ).first()

        return None
    
    @cache_for_request
    def canceled_subscription_billing_cycle_anchor(self):
        """
        Returns cancelation date of most recently canceled subscription
        """
        # Only check for subscriptions if Stripe is enabled
        if settings.STRIPE_ENABLED:
            qs = Organization.objects.prefetch_related('djstripe_customers').filter(
                    djstripe_customers__subscriptions__status='canceled',
                    djstripe_customers__subscriber=self.id,
                ).order_by(
                    '-djstripe_customers__subscriptions__ended_at'
                ).values(
                    anchor=F('djstripe_customers__subscriptions__ended_at'),
                ).first()
            if qs:
                return qs['anchor']
            
        return None

    @classmethod
    def get_from_user_id(cls, user_id: int):
        """
        Get organization that this user is a member of.
        """
        # TODO: validate this is the correct way to get a user's organization
        org = cls.objects.filter(
            organization_users__user__id=user_id,
        ).first()

        return org


class OrganizationUser(AbstractOrganizationUser):
    @property
    def active_subscription_statuses(self):
        """
        Return a list of unique active subscriptions for the organization user.
        """
        try:
            customer = Customer.objects.get(subscriber=self.organization.id)
            subscriptions = Subscription.objects.filter(
                customer=customer, status__in=ACTIVE_STRIPE_STATUSES,
            )

            unique_plans = set()
            for subscription in subscriptions:
                unique_plans.add(str(subscription.plan))

            return list(unique_plans)
        except (Customer.DoesNotExist, Subscription.DoesNotExist):
            return []

    @property
    def active_subscription_status(self):
        """
        Return a comma-separated string of active subscriptions for the organization user.
        """
        return ', '.join(self.active_subscription_statuses)


class OrganizationOwner(AbstractOrganizationOwner):
    pass


class OrganizationInvitation(AbstractOrganizationInvitation):
    pass


create_organization = partial(create_organization_base, model=Organization)
