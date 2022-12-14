# Generated by Django 4.0.4 on 2022-08-16 14:07

from django.conf import settings
import django.core.validators
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0048_alter_user_account_id_alter_user_verification_code_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='article_vendues',
            name='shop',
        ),
        migrations.RemoveField(
            model_name='article_vendues',
            name='user',
        ),
        migrations.RemoveField(
            model_name='article_vendues',
            name='product',
        ),
        migrations.AlterField(
            model_name='user',
            name='account_id',
            field=models.CharField(default=2198670, max_length=7, validators=[django.core.validators.MinLengthValidator(7), django.core.validators.MaxLengthValidator(7)]),
        ),
        migrations.AlterField(
            model_name='user',
            name='verification_code',
            field=models.CharField(default='520219', max_length=9),
        ),
        migrations.CreateModel(
            name='list_product',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('product', models.ManyToManyField(to='authentication.product')),
                ('shop', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='authentication.shop')),
                ('user', models.ForeignKey(default='', on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AddField(
            model_name='article_vendues',
            name='product',
            field=models.ForeignKey(default='', on_delete=django.db.models.deletion.CASCADE, to='authentication.list_product'),
        ),
    ]
