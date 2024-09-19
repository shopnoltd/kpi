# Generated by Django 4.2.11 on 2024-07-24 07:03

from django.db import migrations, models
import kpi.models.abstract_models


class Migration(migrations.Migration):

    dependencies = [
        ('viewer', '0004_update_meta_data_export_types'),
    ]

    operations = [
        migrations.AlterField(
            model_name='instancemodification',
            name='date_created',
            field=models.DateTimeField(default=kpi.models.abstract_models._get_default_datetime),
        ),
        migrations.AlterField(
            model_name='instancemodification',
            name='date_modified',
            field=models.DateTimeField(default=kpi.models.abstract_models._get_default_datetime),
        ),
    ]
