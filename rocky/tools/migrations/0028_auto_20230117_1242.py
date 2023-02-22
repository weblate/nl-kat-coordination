# Generated by Django 3.2.16 on 2023-01-17 12:42

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("tools", "0027_auto_20230103_1721"),
    ]

    operations = [
        migrations.AlterField(
            model_name="organizationmember",
            name="organization",
            field=models.ForeignKey(
                null=True, on_delete=django.db.models.deletion.CASCADE, related_name="members", to="tools.organization"
            ),
        ),
        migrations.AlterField(
            model_name="organizationmember",
            name="user",
            field=models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterUniqueTogether(
            name="organizationmember",
            unique_together={("user", "organization")},
        ),
        migrations.RemoveField(
            model_name="organizationmember",
            name="goal",
        ),
        migrations.RemoveField(
            model_name="organizationmember",
            name="member_role",
        ),
        migrations.RemoveField(
            model_name="organizationmember",
            name="signal_username",
        ),
    ]
