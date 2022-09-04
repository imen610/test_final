import binascii
from decimal import Decimal
from email.policy import default
from math import prod
import os
from tkinter import N
from django.utils import timezone
from django.db import models
from django.db import models
from django.contrib.auth.models import User
from django.contrib.auth.models import AbstractBaseUser,BaseUserManager,PermissionsMixin
from django.forms import CharField, IntegerField
from rest_framework_simplejwt.tokens import RefreshToken
from cashless import settings
import uuid
from django.utils.translation import gettext_lazy as _
from django.core.validators import MinLengthValidator, MaxLengthValidator
import random

class UserManager(BaseUserManager):
    def create_user(self, first_name, last_name, email, username, phone_number, password=None):
        email = self.normalize_email(email)
        account = self.model(first_name=first_name, last_name=last_name, email=email, username=username, phone_number=phone_number)

        account.set_password(password)
        account.save(using=self._db)
        

        return account 

    def create_superuser(self, first_name, last_name, username, email, phone_number, password):
        user = self.create_user(first_name, last_name, email, username, phone_number, password)
        user.is_staff = True 
        user.is_superuser = True

        user.save(using=self._db)
        return user
    # def create_user(self,username,email,password=None):

    #     if username is None:
    #         raise TypeError('Users should have a userneme')
    #     if email is None:
    #         raise TypeError('Users should have an email')
    #     user=self.model(username=username,email=self.normalize_email(email))
    #     user.set_password(password)
    #     user.save()
    #     x=uuid.uuid4().int
    #     print(x)

    #     obj = Wallet(wallet_id=x, balance=0,account=user, is_disabled=False)
    #     obj.save()
    #     return user


    # def create_superuser(self,username,email,password=None):

    #     if password is None:
    #         raise TypeError('Password should not be none')
    #     user=self.create_user(username,email,password)
    #     user.is_superuser=True
    #     user.is_staff=True
    #     user.save()

    #     return user

    

class User(AbstractBaseUser,PermissionsMixin):
    account_id = models.CharField(max_length=7, validators=[MinLengthValidator(7), MaxLengthValidator(7)], default=random.randint(1111111, 9999999))
    membre = models.ManyToManyField(to=settings.AUTH_USER_MODEL,null = True)
    username=models.CharField(max_length=255,unique=True,db_index=True)
    email=models.EmailField(max_length=255,unique=True,db_index=True)
    is_verified=models.BooleanField(default=True)
    is_active=models.BooleanField(default=True)
    is_staff=models.BooleanField(default=False)
    created_at=models.DateTimeField(auto_now_add=True)
    updated_at=models.DateTimeField(auto_now=True)
    first_name= models.CharField(max_length=100,null=True,blank=True)
    last_name=models.CharField(max_length=100,null=True,blank=True)
    phone_number = models.CharField(max_length=17, unique=True, null=True)
    image= models.ImageField(default = "1053244.png", blank=True)
    address=models.CharField(max_length=255, default=None,null=True,blank=True)
    birthday = models.DateField(default=None,null=True,blank=True)
    is_admin = models.BooleanField(default=False)
    is_membre = models.BooleanField(default=False)
    verification_code = models.CharField(default=f"{random.randint(111111,999999)}", max_length=9)
    tax_id = models.CharField(max_length=60, null=True)
    wallet_blocked=models.BooleanField(default=False)

    
    
    USERNAME_FIELD='email'
    REQUIRED_FIELDS=['username']

    objects = UserManager()
 
    def __str__(self):
        return self.email
   
    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh':str(refresh) ,
            'access':str(refresh.access_token)
        }




class product(models.Model):
    name_product = models.CharField(max_length=255,default = None,null =True)
    price_product = models.FloatField(default = None,null =True)
    image_product = models.ImageField(default = "ecommerce-default-product.png", blank=True)
    def __str__(self):
        return f"{self.name_product}"

class Shop(models.Model):
    products=models.ManyToManyField(product)
    name_shop=models.CharField(max_length=255,default = None,null =True)
    address_shop=models.CharField(max_length=255 , default = None,null =True)
    email_shop= models.CharField(max_length=255,default = None,null =True)
    image_shop = models.ImageField(default = "ecommerce-default-product.png", blank=True)

    def __str__(self):
        return f"{self.id}"


def generate_wallet_id():
    while True:
        _id = binascii.b2a_hex(os.urandom(7))
        if Wallet.objects.filter(wallet_id=_id).count() == 0:
            break 
    return _id 
    
def generate_groupe_id():
    while True:
        _id = binascii.b2a_hex(os.urandom(4))
        if Wallet.objects.filter(wallet_id=_id).count() == 0:
            break 
    return _id 


def generate_transaction_id():
    while True:
        trx_id = binascii.b2a_hex(os.urandom(14))
        if Transaction.objects.filter(transaction_id=trx_id).count() == 0:
            break 

    return trx_id 

class Wallet(models.Model):
    account = models.ForeignKey(User,on_delete=models.CASCADE, null =True)
    wallet_id=models.CharField(max_length=17, validators=[MinLengthValidator(17), MaxLengthValidator(17)], default=generate_wallet_id, unique=True)
    creation_date = models.DateTimeField(default=timezone.now)
    is_disabled = models.BooleanField(default=True)
    balance = models.DecimalField(max_digits=10, decimal_places=3, default=0.000)
    maxAmount = models.DecimalField(max_digits=10, decimal_places=3, default=0.000)
   


    def __str__(self):
        return self.account.email


class Transaction(models.Model):
    account = models.ForeignKey(User, on_delete=models.CASCADE)
    transaction_id = models.CharField(max_length=10, validators=[MinLengthValidator(10), MaxLengthValidator(10)], default=generate_transaction_id)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    timestamp = models.DateTimeField(auto_now_add=True)
    to = models.CharField(max_length=60)
    TYPE_CHOICES = (
        ("outflow", "Outflow"),
        ("inflow", "Inflow"),
    )
    type = models.CharField(
        max_length=10, choices=TYPE_CHOICES, default="inflow"
    )


class list_product(models.Model):
    user = models.ForeignKey(User,on_delete=models.CASCADE,default = '')
    product =  models.ManyToManyField(product)
    shop = models.ForeignKey(Shop,on_delete=models.CASCADE)
    total = models.DecimalField(max_digits=10, decimal_places=2, default=00.00)
    timestamp = models.DateTimeField(auto_now_add=True, null = True)


 
class TransactionShop(models.Model):
    account = models.ForeignKey(User, on_delete=models.CASCADE)
    product = models.ForeignKey(list_product, on_delete=models.CASCADE, default=1)
    transaction_id = models.CharField(max_length=10, validators=[MinLengthValidator(10), MaxLengthValidator(10)], default=generate_transaction_id)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    timestamp = models.DateTimeField(auto_now_add=True)
    to = models.CharField(max_length=60)
    TYPE_CHOICES = (
        ("outflow", "Outflow"),
        ("inflow", "Inflow"),
    )
    type = models.CharField(
        max_length=10, choices=TYPE_CHOICES, default="Outflow"
    )
    

    def __str__(self):
        return self.account.email 
    


class Payment(models.Model):
    from_acct = models.ForeignKey(User, on_delete=models.CASCADE)
    to_acct = models.CharField(max_length=60)
    amount = models.DecimalField(max_digits=10, decimal_places=2)

    def __str__(self):
        return self.from_acct.email 




class shop_account(models.Model):
    account = models.ForeignKey(Shop, on_delete=models.CASCADE)
    wallet_id = models.CharField(max_length=17, validators=[MinLengthValidator(17), MaxLengthValidator(17)], default=generate_wallet_id, unique=True)
    is_disabled = models.BooleanField(default=False)
    balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    
    def __str__(self) :
        return self.account.email


class Blocked_Product(models.Model):
    product = models.ForeignKey(product,on_delete=models.CASCADE,null= True)
    user  = models.ForeignKey(User,on_delete=models.CASCADE)
    blocked = models.BooleanField(default=False)



class group(models.Model):
    user = models.ForeignKey(User,on_delete=models.CASCADE)
    id_groupe = models.CharField(max_length=4, validators=[MinLengthValidator(4), MaxLengthValidator(4)], default=generate_groupe_id)
    is_superuser = models.BooleanField(default = False)
    is_member = models.BooleanField(default =False)



class article_vendues(models.Model):
    product =models.ForeignKey(list_product,on_delete=models.CASCADE,default = '')
    total = models.DecimalField(max_digits=10, decimal_places=2)
    code_NFC = models.CharField(max_length=17, validators=[MinLengthValidator(17), MaxLengthValidator(17)], default=generate_wallet_id, unique=True)

## il va prendre un code NFC ET IL VA RETOURNER UNE LISTE DE PRODUiTS W TOTALe W codeNFC 