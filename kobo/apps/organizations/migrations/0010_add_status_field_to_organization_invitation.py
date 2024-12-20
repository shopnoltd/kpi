# Generated by Django 4.2.15 on 2024-12-20 14:31

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('organizations', '0009_update_db_state_with_auth_user'),
    ]

    operations = [
        migrations.AddField(
            model_name='organizationinvitation',
            name='status',
            field=models.CharField(
                choices=[
                    ('accepted', 'Accepted'),
                    ('cancelled', 'Cancelled'),
                    ('complete', 'Complete'),
                    ('declined', 'Declined'),
                    ('expired', 'Expired'),
                    ('failed', 'Failed'),
                    ('in_progress', 'In Progress'),
                    ('pending', 'Pending'),
                    ('resent', 'Resent'),
                ],
                default='pending',
                max_length=11,
            ),
        ),
    ]
