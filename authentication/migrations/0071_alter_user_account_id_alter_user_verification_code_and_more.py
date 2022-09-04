# Generated by Django 4.0.4 on 2022-08-28 11:35

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0070_wallet_max_amount_alter_user_account_id_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='account_id',
            field=models.CharField(default=9504146, max_length=7, validators=[django.core.validators.MinLengthValidator(7), django.core.validators.MaxLengthValidator(7)]),
        ),
        migrations.AlterField(
            model_name='user',
            name='verification_code',
            field=models.CharField(default='221918', max_length=9),
        ),
        migrations.AlterField(
            model_name='wallet',
            name='max_amount',
            field=models.DecimalField(decimal_places=3, default=0.0, max_digits=10),
        ),
    ]
