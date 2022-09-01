# Generated by Django 4.0.4 on 2022-07-28 10:32

import authentication.models
import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0016_alter_group_id_groupe_alter_user_account_id_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='group',
            name='is_member',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='group',
            name='is_superuser',
            field=models.BooleanField(default=True),
        ),
        migrations.AlterField(
            model_name='group',
            name='id_groupe',
            field=models.CharField(default=authentication.models.generate_groupe_id, max_length=4, unique=True, validators=[django.core.validators.MinLengthValidator(4), django.core.validators.MaxLengthValidator(4)]),
        ),
        migrations.AlterField(
            model_name='user',
            name='account_id',
            field=models.CharField(default=8526004, max_length=7, validators=[django.core.validators.MinLengthValidator(7), django.core.validators.MaxLengthValidator(7)]),
        ),
        migrations.AlterField(
            model_name='user',
            name='verification_code',
            field=models.CharField(default='578338', max_length=9),
        ),
    ]