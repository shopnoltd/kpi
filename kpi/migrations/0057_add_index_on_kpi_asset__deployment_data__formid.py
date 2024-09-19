# Generated by Django 4.2.15 on 2024-09-11 19:21

import django.contrib.postgres.indexes
from django.conf import settings
from django.db import migrations, models


def manually_create_indexes_instructions(apps, schema_editor):
    print(
        """
        !!! ATTENTION !!!
        If you have existing projects you need to run the SQL queries below in PostgreSQL directly:

           > CREATE INDEX CONCURRENTLY "deployment_data__formid_idx" ON kpi_asset USING btree ((("_deployment_data" -> 'formid')));

        Otherwise, project views will perform very poorly.
        """
    )


def manually_drop_indexes_instructions(apps, schema_editor):
    print(
        """
        !!! ATTENTION !!!
        Run the SQL queries below in PostgreSQL directly:

           > DROP INDEX IF EXISTS "deployment_data__formid_idx";

        """
    )


class Migration(migrations.Migration):

    dependencies = [
        ('kpi', '0056_fix_add_submission_bad_permission_assignment'),
    ]

    if settings.SKIP_HEAVY_MIGRATIONS:
        operations = [
            migrations.RunPython(
                manually_create_indexes_instructions,
                manually_drop_indexes_instructions,
            )
        ]
    else:
        operations = [
            migrations.AddIndex(
                model_name='asset',
                index=django.contrib.postgres.indexes.BTreeIndex(
                    models.F('_deployment_data__formid'),
                    name='deployment_data__formid_idx',
                ),
            ),
        ]
