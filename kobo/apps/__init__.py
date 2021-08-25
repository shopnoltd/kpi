# coding: utf-8
import kombu.exceptions
from django.apps import AppConfig
from django.core.checks import register, Tags

from kpi.utils.two_database_configuration_checker import \
    TwoDatabaseConfigurationChecker


class KpiConfig(AppConfig):
    name = 'kpi'

    def ready(self, *args, **kwargs):
        # Once it's okay to read from the database, apply the user-desired
        # autoscaling configuration for Celery workers
        from kobo.celery import update_concurrency_from_constance
        try:
            update_concurrency_from_constance.delay()
        except kombu.exceptions.OperationalError as e:
            # It's normal for Django to start without access to a message
            # broker, e.g. while running `./manage.py collectstatic`
            # during a Docker image build
            pass
        return super().ready(*args, **kwargs)


register(TwoDatabaseConfigurationChecker().as_check(), Tags.database)
