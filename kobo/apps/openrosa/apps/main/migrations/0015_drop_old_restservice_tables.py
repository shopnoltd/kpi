# Generated by Django 4.2.11 on 2024-07-31 15:59

from django.db import migrations, connections
from django.conf import settings


KC_REST_SERVICES_TABLES = [
    'restservice_restservice',
]


def get_operations():
    if settings.TESTING or settings.SKIP_HEAVY_MIGRATIONS:
        # Skip this migration if running in test environment or because we want
        # to voluntarily skip it.
        return []

    tables = KC_REST_SERVICES_TABLES
    operations = []

    sql = """
        SELECT con.conname
           FROM pg_catalog.pg_constraint con
                INNER JOIN pg_catalog.pg_class rel
                           ON rel.oid = con.conrelid
                INNER JOIN pg_catalog.pg_namespace nsp
                           ON nsp.oid = connamespace
           WHERE nsp.nspname = 'public'
                 AND rel.relname = %s;
    """
    with connections[settings.OPENROSA_DB_ALIAS].cursor() as cursor:
        drop_table_queries = []
        for table in tables:
            cursor.execute(sql, [table])
            drop_index_queries = []
            for row in cursor.fetchall():
                if not row[0].endswith('_pkey'):
                    drop_index_queries.append(
                        f'ALTER TABLE public.{table} DROP CONSTRAINT {row[0]};'
                    )
            drop_table_queries.append(f'DROP TABLE IF EXISTS {table};')
            operations.append(
                migrations.RunSQL(
                    sql=''.join(drop_index_queries),
                    reverse_sql=migrations.RunSQL.noop,
                )
            )

        operations.append(
            migrations.RunSQL(
                sql=''.join(drop_table_queries),
                reverse_sql=migrations.RunSQL.noop,
            )
        )

    return operations


def print_migration_warning(apps, schema_editor):
    if settings.TESTING or settings.SKIP_HEAVY_MIGRATIONS:
        return
    print(
        """
        This migration might take a while. If it is too slow, you may want to
        re-run migrations with SKIP_HEAVY_MIGRATIONS=True and apply this one
        manually from the django shell.
        """
    )


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0014_drop_old_formdisclaimer_tables'),
    ]

    operations = [migrations.RunPython(print_migration_warning), *get_operations()]
