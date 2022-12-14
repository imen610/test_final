# Generated by Django 4.0.4 on 2022-08-16 13:16

import authentication.models
from django.conf import settings
import django.core.validators
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0035_remove_article_vendues_user_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='article_vendues',
            name='user',
            field=models.ForeignKey(default='', on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='article_vendues',
            name='code_NFC',
            field=models.CharField(default=authentication.models.generate_wallet_id, max_length=17, unique=True, validators=[django.core.validators.MinLengthValidator(17), django.core.validators.MaxLengthValidator(17)]),
        ),
        migrations.RemoveField(
            model_name='article_vendues',
            name='product',
        ),
        migrations.AddField(
            model_name='article_vendues',
            name='product',
            field=models.ManyToManyField(to='authentication.product'),
        ),
        migrations.AlterField(
            model_name='user',
            name='account_id',
            field=models.CharField(default=9179658, max_length=7, validators=[django.core.validators.MinLengthValidator(7), django.core.validators.MaxLengthValidator(7)]),
        ),
        migrations.AlterField(
            model_name='user',
            name='verification_code',
            field=models.CharField(default='983736', max_length=9),
        ),
        migrations.DeleteModel(
            name='list_articles',
        ),
    ]
