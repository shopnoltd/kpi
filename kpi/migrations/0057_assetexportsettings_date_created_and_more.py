# Generated by Django 4.2.11 on 2024-07-22 06:27

from django.db import migrations, models
import kpi.fields.file
import kpi.models.abstract_models
import kpi.models.asset_file


class Migration(migrations.Migration):

    dependencies = [
        ('kpi', '0056_fix_add_submission_bad_permission_assignment'),
    ]

    operations = [
        migrations.AddField(
            model_name='assetexportsettings',
            name='date_created',
            field=models.DateTimeField(default=kpi.models.abstract_models.get_current_time),
        ),
        migrations.AddField(
            model_name='assetversion',
            name='date_created',
            field=models.DateTimeField(default=kpi.models.abstract_models.get_current_time),
        ),
        migrations.AlterField(
            model_name='asset',
            name='date_created',
            field=models.DateTimeField(default=kpi.models.abstract_models.get_current_time),
        ),
        migrations.AlterField(
            model_name='asset',
            name='date_modified',
            field=models.DateTimeField(default=kpi.models.abstract_models.get_current_time),
        ),
        migrations.AlterField(
            model_name='assetexportsettings',
            name='date_modified',
            field=models.DateTimeField(default=kpi.models.abstract_models.get_current_time),
        ),
        migrations.AlterField(
            model_name='assetfile',
            name='date_created',
            field=models.DateTimeField(default=kpi.models.abstract_models.get_current_time),
        ),
        migrations.AlterField(
            model_name='assetfile',
            name='date_modified',
            field=models.DateTimeField(default=kpi.models.abstract_models.get_current_time),
        ),
        migrations.AlterField(
            model_name='assetuserpartialpermission',
            name='date_created',
            field=models.DateTimeField(default=kpi.models.abstract_models.get_current_time),
        ),
        migrations.AlterField(
            model_name='assetuserpartialpermission',
            name='date_modified',
            field=models.DateTimeField(default=kpi.models.abstract_models.get_current_time),
        ),
        migrations.AlterField(
            model_name='assetversion',
            name='date_modified',
            field=models.DateTimeField(default=kpi.models.abstract_models.get_current_time),
        ),
    ]
