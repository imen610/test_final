# Generated by Django 4.0.4 on 2022-08-24 07:43

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0067_remove_list_product_timestamp_alter_user_account_id_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='account_id',
            field=models.CharField(default=3398220, max_length=7, validators=[django.core.validators.MinLengthValidator(7), django.core.validators.MaxLengthValidator(7)]),
        ),
        migrations.AlterField(
            model_name='user',
            name='verification_code',
            field=models.CharField(default='363507', max_length=9),
        ),
        migrations.AlterField(
            model_name='wallet',
            name='is_disabled',
            field=models.BooleanField(default=True),
        ),
    ]