# Generated by Django 4.0.4 on 2022-07-28 21:50

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0027_alter_transaction_transaction_id_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='account_id',
            field=models.CharField(default=9056287, max_length=7, validators=[django.core.validators.MinLengthValidator(7), django.core.validators.MaxLengthValidator(7)]),
        ),
        migrations.AlterField(
            model_name='user',
            name='verification_code',
            field=models.CharField(default='991959', max_length=9),
        ),
    ]