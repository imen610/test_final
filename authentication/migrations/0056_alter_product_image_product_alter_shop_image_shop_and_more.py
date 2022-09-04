# Generated by Django 4.0.4 on 2022-08-18 22:06

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0055_alter_user_account_id_alter_user_image_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='product',
            name='image_product',
            field=models.ImageField(blank=True, default='ecommerce-default-product.png', upload_to=''),
        ),
        migrations.AlterField(
            model_name='shop',
            name='image_shop',
            field=models.ImageField(blank=True, default='ecommerce-default-product.png', upload_to=''),
        ),
        migrations.AlterField(
            model_name='user',
            name='account_id',
            field=models.CharField(default=5203745, max_length=7, validators=[django.core.validators.MinLengthValidator(7), django.core.validators.MaxLengthValidator(7)]),
        ),
        migrations.AlterField(
            model_name='user',
            name='verification_code',
            field=models.CharField(default='378740', max_length=9),
        ),
    ]
