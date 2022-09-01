# Generated by Django 4.0.4 on 2022-08-16 13:51

import authentication.models
from django.conf import settings
import django.core.validators
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0047_alter_user_account_id_alter_user_verification_code'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='account_id',
            field=models.CharField(default=5101936, max_length=7, validators=[django.core.validators.MinLengthValidator(7), django.core.validators.MaxLengthValidator(7)]),
        ),
        migrations.AlterField(
            model_name='user',
            name='verification_code',
            field=models.CharField(default='366064', max_length=9),
        ),
        migrations.CreateModel(
            name='article_vendues',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('total', models.DecimalField(decimal_places=2, max_digits=10)),
                ('code_NFC', models.CharField(default=authentication.models.generate_wallet_id, max_length=17, unique=True, validators=[django.core.validators.MinLengthValidator(17), django.core.validators.MaxLengthValidator(17)])),
                ('product', models.ManyToManyField(to='authentication.product')),
                ('shop', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='authentication.shop')),
                ('user', models.ForeignKey(default='', on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
