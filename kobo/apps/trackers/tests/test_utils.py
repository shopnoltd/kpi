from django.utils import timezone
from djstripe.models import (
    Customer,
    PaymentIntent,
    Charge,
    Price,
    Product,
    Subscription,
)
from model_bakery import baker

from kobo.apps.kobo_auth.shortcuts import User
from kobo.apps.organizations.models import Organization, OrganizationUser
from kobo.apps.stripe.constants import USAGE_LIMIT_MAP_STRIPE, USAGE_LIMIT_MAP
from kobo.apps.stripe.tests.utils import generate_plan_subscription
from kobo.apps.trackers.utils import (
    get_organization_remaining_usage,
    update_nlp_counter
)
from kpi.models.asset import Asset
from kpi.tests.kpi_test_case import BaseTestCase


class TrackersUtilitiesTestCase(BaseTestCase):
    fixtures = ['test_data']

    def setUp(self):
        self.organization = baker.make(
            Organization, id='123456abcdef', name='test organization'
        )
        self.someuser = User.objects.get(username='someuser')
        self.anotheruser = User.objects.get(username='anotheruser')
        self.organization.add_user(self.someuser, is_admin=True)

        self.asset = Asset.objects.create(
            content={'survey': [{'type': 'text', 'label': 'q1', 'name': 'q1'}]},
            owner=self.someuser,
            asset_type='survey',
            name='test asset',
        )
        self.asset.deploy(backend='mock', active=True)

    def _make_payment(
        self, price, customer, payment_status='succeeded', refunded=False, quantity=1,
    ):
        payment_total = quantity * 2000
        payment_intent = baker.make(
            PaymentIntent,
            customer=customer,
            status=payment_status,
            payment_method_types=['card'],
            livemode=False,
            amount=payment_total,
            amount_capturable=payment_total,
            amount_received=payment_total,
        )
        charge = baker.prepare(
            Charge,
            customer=customer,
            refunded=refunded,
            created=timezone.now(),
            payment_intent=payment_intent,
            paid=True,
            status=payment_status,
            livemode=False,
            amount_refunded=0 if refunded else payment_total,
            amount=payment_total,
        )
        charge.metadata = {
            'price_id': price.id,
            'organization_id': self.organization.id,
            'quantity': quantity,
            **(price.product.metadata or {}),
        }
        charge.save()

    def _create_product(self, product_metadata):
        product = baker.make(
            Product,
            active=True,
            metadata=product_metadata,
        )
        price = baker.make(
            Price, active=True, product=product, type='one_time'
        )
        return product, price

    def _test_organization_usage_utils(self, usage_type):
        stripe_key = f'{USAGE_LIMIT_MAP_STRIPE[usage_type]}_limit'
        sub_metadata = {
            stripe_key: 1234,
            'product_type': 'plan',
            'plan_type': 'enterprise',
        }
        subscription = generate_plan_subscription(self.organization, metadata=sub_metadata)
        addon_metadata = {
            'product_type': 'addon_onetime',
            stripe_key: 12345,
            'valid_tags': 'all',
        }
        product, price = self._create_product(addon_metadata)
        self._make_payment(price, subscription.customer, quantity=2)

        expected_limit = 12345*2 + 1234
        remaining = get_organization_remaining_usage(self.organization, usage_type)
        assert remaining == expected_limit

        service_key = USAGE_LIMIT_MAP[usage_type]
        update_nlp_counter(service_key, 1000, self.someuser.id, self.asset.id)

        remaining = get_organization_remaining_usage(self.organization, usage_type)
        assert remaining == expected_limit - 1000


    def test_org_usage_seconds(self):
        self._test_organization_usage_utils('seconds')
