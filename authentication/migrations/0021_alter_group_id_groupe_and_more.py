# Generated by Django 4.0.4 on 2022-07-28 22:16

import authentication.models
import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0021_alter_group_id_groupe_alter_user_account_id_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='group',
            name='id_groupe',
            field=models.CharField(default=authentication.models.generate_groupe_id, max_length=4, validators=[django.core.validators.MinLengthValidator(4), django.core.validators.MaxLengthValidator(4)]),
        ),
        migrations.AlterField(
            model_name='transaction',
            name='transaction_id',
            field=models.CharField(default=authentication.models.generate_transaction_id, max_length=17, validators=[django.core.validators.MinLengthValidator(17), django.core.validators.MaxLengthValidator(17)]),
        ),
        migrations.AlterField(
            model_name='user',
            name='account_id',
            field=models.CharField(default=5277425, max_length=7, validators=[django.core.validators.MinLengthValidator(7), django.core.validators.MaxLengthValidator(7)]),
        ),
        migrations.AlterField(
            model_name='user',
            name='verification_code',
            field=models.CharField(default='538450', max_length=9),
        ),
    ]
