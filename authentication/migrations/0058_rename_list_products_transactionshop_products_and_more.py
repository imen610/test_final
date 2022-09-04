# Generated by Django 4.0.4 on 2022-08-19 07:44

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0057_transactionshop_list_products_alter_user_account_id_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='transactionshop',
            old_name='list_products',
            new_name='products',
        ),
        migrations.AlterField(
            model_name='user',
            name='account_id',
            field=models.CharField(default=9467758, max_length=7, validators=[django.core.validators.MinLengthValidator(7), django.core.validators.MaxLengthValidator(7)]),
        ),
        migrations.AlterField(
            model_name='user',
            name='verification_code',
            field=models.CharField(default='421579', max_length=9),
        ),
    ]
