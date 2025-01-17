# Generated by Django 4.2.15 on 2024-10-25 16:08

from django.core.paginator import Paginator
from django.db import migrations


def update_organization_names(apps, schema_editor):
    Organization = apps.get_model('organizations', 'Organization')
    OrganizationUser = apps.get_model('organizations', 'OrganizationUser')

    page_size = 2000
    paginator = Paginator(
        OrganizationUser.objects.filter(organizationowner__isnull=False)
        .select_related('user', 'organization', 'user__extra_details')
        .order_by('pk'),
        page_size,
    )
    for page in paginator.page_range:
        organization_users = paginator.page(page).object_list
        organizations = []
        for organization_user in organization_users:
            user = organization_user.user
            organization = organization_user.organization
            if (
                organization.name
                and organization.name.strip() != ''
                and organization.name.startswith(user.username)
            ):
                update = False
                if organization_name := user.extra_details.data.get(
                    'organization', ''
                ).strip():
                    update = True
                    organization.name = organization_name

                if organization_website := user.extra_details.data.get(
                    'organization_website', ''
                ).strip():
                    update = True
                    organization.website = organization_website

                if organization_type := user.extra_details.data.get(
                    'organization_type', ''
                ).strip():
                    update = True
                    organization.organization_type = organization_type

                if update:
                    organizations.append(organization)

        if organizations:
            Organization.objects.bulk_update(
                organizations, ['name', 'organization_type', 'website']
            )


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('organizations', '0006_add_organization_type_and_website'),
    ]

    operations = [migrations.RunPython(update_organization_names, noop)]
