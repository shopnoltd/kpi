from django.conf import settings
from django.db.models import Sum, Q
from django.db.models.functions import Coalesce
from django.utils import timezone
from rest_framework import serializers
from rest_framework.fields import empty

from kobo.apps.kobo_auth.shortcuts import User
from kobo.apps.organizations.models import Organization
from kobo.apps.organizations.utils import (
    get_monthly_billing_dates,
    get_yearly_billing_dates,
)
from kobo.apps.stripe.constants import ACTIVE_STRIPE_STATUSES
from kobo.apps.trackers.models import NLPUsageCounter
from kpi.deployment_backends.kc_access.shadow_models import (
    KobocatXForm,
    KobocatDailyXFormSubmissionCounter,
)
from kpi.deployment_backends.kobocat_backend import KobocatDeploymentBackend
from kpi.models.asset import Asset
from kpi.utils.usage_calculator import UsageCalculator


class AssetUsageSerializer(serializers.HyperlinkedModelSerializer):
    asset = serializers.HyperlinkedIdentityField(
        lookup_field='uid',
        view_name='asset-detail',
    )
    asset__name = serializers.ReadOnlyField(source='name')
    nlp_usage_current_month = serializers.SerializerMethodField()
    nlp_usage_current_year = serializers.SerializerMethodField()
    nlp_usage_all_time = serializers.SerializerMethodField()
    storage_bytes = serializers.SerializerMethodField()
    submission_count_current_month = serializers.SerializerMethodField()
    submission_count_current_year = serializers.SerializerMethodField()
    submission_count_all_time = serializers.SerializerMethodField()

    class Meta:
        model = Asset
        lookup_field = 'uid'
        fields = (
            'asset',
            'asset__name',
            'nlp_usage_current_month',
            'nlp_usage_current_year',
            'nlp_usage_all_time',
            'storage_bytes',
            'submission_count_current_month',
            'submission_count_current_year',
            'submission_count_all_time',
        )

    def __init__(self, instance=None, data=empty, **kwargs):
        super().__init__(instance=instance, data=data, **kwargs)
        organization = self.context.get('organization')
        self._month_start, _ = get_monthly_billing_dates(organization)
        self._year_start, _ = get_yearly_billing_dates(organization)

    def get_nlp_usage_current_month(self, asset):
        return self._get_nlp_tracking_data(asset, self._month_start)

    def get_nlp_usage_current_year(self, asset):
        return self._get_nlp_tracking_data(asset, self._year_start)

    def get_nlp_usage_all_time(self, asset):
        return self._get_nlp_tracking_data(asset)

    def get_submission_count_current_month(self, asset):
        if not asset.has_deployment:
            return 0
        return asset.deployment.submission_count_since_date(self._month_start)

    def get_submission_count_current_year(self, asset):
        if not asset.has_deployment:
            return 0
        return asset.deployment.submission_count_since_date(self._year_start)

    def get_submission_count_all_time(self, asset):
        if not asset.has_deployment:
            return 0

        return asset.deployment.submission_count_since_date()

    def get_storage_bytes(self, asset):
        # Get value from asset deployment (if it has deployment)
        if not asset.has_deployment:
            return 0

        return asset.deployment.attachment_storage_bytes

    def _get_nlp_tracking_data(self, asset, start_date=None):
        if not asset.has_deployment:
            return {
                'total_nlp_asr_seconds': 0,
                'total_nlp_mt_characters': 0,
            }
        return KobocatDeploymentBackend.nlp_tracking_data(
            asset_ids=[asset.id], start_date=start_date
        )


class CustomAssetUsageSerializer(AssetUsageSerializer):
    deployment_status = serializers.SerializerMethodField()

    class Meta(AssetUsageSerializer.Meta):
        fields = AssetUsageSerializer.Meta.fields + ('deployment_status',)

    def get_deployment_status(self, asset):
        return asset.deployment_status


class ServiceUsageSerializer(serializers.Serializer):
    total_nlp_usage = serializers.SerializerMethodField()
    total_storage_bytes = serializers.SerializerMethodField()
    total_submission_count = serializers.SerializerMethodField()
    current_month_start = serializers.SerializerMethodField()
    current_month_end = serializers.SerializerMethodField()
    current_year_start = serializers.SerializerMethodField()
    current_year_end = serializers.SerializerMethodField()

    def __init__(self, instance=None, data=empty, **kwargs):
        super().__init__(instance=instance, data=data, **kwargs)
        organization = None
        organization_id = self.context.get('organization_id', None)
        if organization_id:
            organization = Organization.objects.filter(
                organization_users__user_id=instance.id,
                id=organization_id,
            ).first()
        self.calculator = UsageCalculator(instance, organization)

    def get_total_nlp_usage(self, user):
        return self.calculator.get_nlp_usage_counters()

    def get_total_submission_count(self, user):
        return self.calculator.get_submission_counters()

    def get_total_storage_bytes(self, user):
        return self.calculator.get_storage_usage()

    def get_current_month_start(self, user):
        return self.calculator.current_month_start.isoformat()

    def get_current_month_end(self, user):
        return self.calculator.current_month_end.isoformat()

    def get_current_year_start(self, user):
        return self.calculator.current_year_start.isoformat()

    def get_current_year_end(self, user):
        return self.calculator.current_year_end.isoformat()
