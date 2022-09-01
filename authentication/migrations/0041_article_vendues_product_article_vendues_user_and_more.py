# Generated by Django 4.0.4 on 2022-08-16 13:41

from django.conf import settings
import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0040_remove_article_vendues_product_alter_user_account_id_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='article_vendues',
            name='product',
            field=models.ManyToManyField(to='authentication.product'),
        ),
        migrations.AddField(
            model_name='article_vendues',
            name='user',
            field=models.ManyToManyField(to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='user',
            name='account_id',
            field=models.CharField(default=6846869, max_length=7, validators=[django.core.validators.MinLengthValidator(7), django.core.validators.MaxLengthValidator(7)]),
        ),
        migrations.AlterField(
            model_name='user',
            name='verification_code',
            field=models.CharField(default='913534', max_length=9),
        ),
    ]
