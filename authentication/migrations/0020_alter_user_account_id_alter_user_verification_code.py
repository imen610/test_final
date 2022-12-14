# Generated by Django 4.0.4 on 2022-07-28 10:38

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0019_alter_user_account_id_alter_user_verification_code'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='account_id',
            field=models.CharField(default=6791302, max_length=7, validators=[django.core.validators.MinLengthValidator(7), django.core.validators.MaxLengthValidator(7)]),
        ),
        migrations.AlterField(
            model_name='user',
            name='verification_code',
            field=models.CharField(default='289749', max_length=9),
        ),
    ]
