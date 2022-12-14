# Generated by Django 4.0.4 on 2022-07-28 10:36

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0017_group_is_member_group_is_superuser_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='group',
            name='is_superuser',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='user',
            name='account_id',
            field=models.CharField(default=7706151, max_length=7, validators=[django.core.validators.MinLengthValidator(7), django.core.validators.MaxLengthValidator(7)]),
        ),
        migrations.AlterField(
            model_name='user',
            name='verification_code',
            field=models.CharField(default='185644', max_length=9),
        ),
    ]
