# Generated by Django 4.0.4 on 2022-07-14 09:31

import authentication.models
from django.conf import settings
import django.core.validators
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('account_id', models.CharField(default=6113971, max_length=7, validators=[django.core.validators.MinLengthValidator(7), django.core.validators.MaxLengthValidator(7)])),
                ('username', models.CharField(db_index=True, max_length=255, unique=True)),
                ('email', models.EmailField(db_index=True, max_length=255, unique=True)),
                ('is_verified', models.BooleanField(default=True)),
                ('is_active', models.BooleanField(default=True)),
                ('is_staff', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('first_name', models.CharField(blank=True, max_length=100, null=True)),
                ('last_name', models.CharField(blank=True, max_length=100, null=True)),
                ('phone_number', models.CharField(max_length=17, null=True, unique=True)),
                ('image', models.ImageField(blank=True, null=True, upload_to='')),
                ('address', models.CharField(blank=True, default=None, max_length=255, null=True)),
                ('birthday', models.DateField(blank=True, default=None, null=True)),
                ('is_admin', models.BooleanField(default=False)),
                ('is_membre', models.BooleanField(default=False)),
                ('verification_code', models.CharField(default='113038', max_length=9)),
                ('tax_id', models.CharField(max_length=60, null=True)),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.group', verbose_name='groups')),
                ('membre', models.ManyToManyField(null=True, to=settings.AUTH_USER_MODEL)),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.permission', verbose_name='user permissions')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='product',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name_product', models.CharField(default=None, max_length=255, null=True)),
                ('price_product', models.FloatField(default=None, null=True)),
                ('image_product', models.ImageField(blank=True, null=True, upload_to='')),
            ],
        ),
        migrations.CreateModel(
            name='Shop',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name_shop', models.CharField(default=None, max_length=255, null=True)),
                ('address_shop', models.CharField(default=None, max_length=255, null=True)),
                ('email_shop', models.CharField(default=None, max_length=255, null=True)),
                ('image_shop', models.ImageField(blank=True, null=True, upload_to='')),
                ('products', models.ManyToManyField(to='authentication.product')),
            ],
        ),
        migrations.CreateModel(
            name='Wallet',
            fields=[
                ('id', models.IntegerField(default=0, primary_key=True, serialize=False)),
                ('wallet_id', models.CharField(default=authentication.models.generate_wallet_id, max_length=17, unique=True, validators=[django.core.validators.MinLengthValidator(17), django.core.validators.MaxLengthValidator(17)])),
                ('creation_date', models.DateTimeField(null=True, verbose_name='creation date')),
                ('is_disabled', models.BooleanField(default=False)),
                ('balance', models.DecimalField(decimal_places=3, default=0.0, max_digits=10)),
                ('account', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('shop', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='authentication.shop')),
            ],
            options={
                'ordering': ('-creation_date',),
            },
        ),
        migrations.CreateModel(
            name='Transaction',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('transaction_id', models.CharField(default=authentication.models.generate_transaction_id, max_length=10, validators=[django.core.validators.MinLengthValidator(10), django.core.validators.MaxLengthValidator(10)])),
                ('amount', models.DecimalField(decimal_places=2, max_digits=10)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('to', models.CharField(max_length=60)),
                ('account', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Payment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('to_acct', models.CharField(max_length=60)),
                ('amount', models.DecimalField(decimal_places=2, max_digits=10)),
                ('from_acct', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
