# Generated by Django 2.2.28 on 2022-06-28 22:20

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0009_userprofile_attachment_storage_bytes'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userprofile',
            name='metadata',
            field=models.JSONField(blank=True, default=dict),
        ),
    ]