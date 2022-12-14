# Generated by Django 4.0.4 on 2022-08-16 13:43

from django.conf import settings
import django.core.validators
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0041_article_vendues_product_article_vendues_user_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='article_vendues',
            name='user',
        ),
        migrations.AddField(
            model_name='article_vendues',
            name='user',
            field=models.ForeignKey(default='', on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='user',
            name='account_id',
            field=models.CharField(default=7367177, max_length=7, validators=[django.core.validators.MinLengthValidator(7), django.core.validators.MaxLengthValidator(7)]),
        ),
        migrations.AlterField(
            model_name='user',
            name='verification_code',
            field=models.CharField(default='710537', max_length=9),
        ),
    ]
