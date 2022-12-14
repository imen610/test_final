# Generated by Django 4.0.4 on 2022-08-19 13:56

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0066_alter_list_product_timestamp_alter_user_account_id_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='list_product',
            name='timestamp',
        ),
        migrations.AlterField(
            model_name='user',
            name='account_id',
            field=models.CharField(default=2329212, max_length=7, validators=[django.core.validators.MinLengthValidator(7), django.core.validators.MaxLengthValidator(7)]),
        ),
        migrations.AlterField(
            model_name='user',
            name='verification_code',
            field=models.CharField(default='487792', max_length=9),
        ),
    ]
