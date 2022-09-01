from pyexpat import model
import uuid
from pkg_resources import require
import requests
from rest_framework.exceptions import APIException
from asyncio.log import logger
from http.client import OK

from cashless import settings
from .models import Blocked_Product, User, Shop, Wallet, group, list_product,product, shop_account
from rest_framework import serializers 
from django.contrib.auth import authenticate
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
import pdb;
from rest_framework_jwt.settings import api_settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str,force_str , smart_bytes 
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from cashless.utils import Util
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str,force_str , smart_bytes ,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.db.models import Sum



class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ( "email", "username", "phone_number", "password")
        extra_kwargs = {
            "password": {
                "write_only": True
            }
        }

    def create(self, validated_data):
       
        user = models.User.objects.create(
            username = validated_data["username"],
            phone_number = validated_data["phone_number"],
            email = validated_data["email"],
            
        )

        user.set_password(validated_data["password"])
        user.save()
        x=uuid.uuid4().int
        y=uuid.uuid4().int
        print(x)
       
        obj = Wallet(wallet_id=x, balance=0,account=user, is_disabled=True)
        
        obj.save()
        user.wallet_blocked = True
        user.save()
        grp =group(user=user,id_groupe=y,is_superuser = True, is_member =False)
        grp.save()
        

        return user 


class VerifySerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=60)


# class RegisterSerializer(serializers.ModelSerializer):
  
#     class Meta:
#         model= User
#         fields=['email','username','password']

#         extra_kwargs={
#             'password':{'write_only':True}
#         }


#         def validate(self,attrs):
#             email = attrs.get('email','')
#             username = attrs.get('username','')

#             if not username.isalnum():
#                 raise serializers.ValidationError(
#                     'the username should only contain alphanumeric characters'
#                 )
#             return attrs

#         def create(self,validated_data):
#             user = User.objects.create_user(**validated_data)
#             # x=uuid.uuid4().int
#             # print(x)

#             # obj = Wallet(wallet_id=x, balance=0,account=user, is_disabled=False)
#             # obj.save()
#             # return user

        

class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model=User
        fields=['token']


class LoginSerializer(serializers.Serializer):    
    email=serializers.EmailField()
    password = serializers.CharField()

    def get_tokens(self,user):
        user = user

        return {
            'refresh': user.tokens()['refresh'],
            'access': user.tokens()['access'],
            'hello ':'hello imen'
        }
    def save(self):
        email = self.validated_data['email']
        password = self.validated_data['password']
        #user = auth.authenticate(email=email, password=password)
        user=User.objects.filter(email=email,password=password).first()
        
        if user:
            print(user.email)
            token=self.get_tokens(user)
            print(token)
            msg={
                "username":user.username,
                "email":user.email,
                "image":user.image,
                "token":token
            }
            
        elif not user:
            #raise AuthenticationFailed('Invalid credentials, try again')
            msg={'error':'user not found'}
        elif not user.is_active:
            
            msg={'error''Account disabled, contact admin'}
            #raise AuthenticationFailed('Account disabled, contact admin')
        elif not user.is_verified:
            msg={'error':'Email is not verified'}
            #raise AuthenticationFailed('Email is not verified')  
        else:
            msg={'error':'Unknown Error'}           
        return msg
   


class RestPasswordEmailRequestSerialiser(serializers.Serializer):
    email=serializers.EmailField(min_length=2)
    
    class Meta:
        fields  =['email']
class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length = 6, max_length=68,write_only=True)
    token = serializers.CharField(min_length = 1,write_only=True)
    uidb64 = serializers.CharField(min_length = 1,write_only=True)
    email = serializers.CharField(min_length = 1,write_only=True)
    class Meta:
        fields=['password','token','uidb64','email']

    def validate(self,attrs):
        try:
            password=attrs.get('password')
            token = attrs.get('token')
            email = attrs.get('email')
            uidb64 = attrs.get('uidb64')
            # id=force_str(urlsafe_base64_decode(uidb64))
            # print(self.id)
            
            user=User.objects.get(email=email)
            if not PasswordResetTokenGenerator().check_token(user,token):
                raise AuthenticationFailed(' invalid',401)
            user.set_password(password)
            user.save()
        except Exception as e :
            raise AuthenticationFailed('link is invalid',401)
        return super().validate(attrs)



class UserSerializer(serializers.ModelSerializer):
    """
    user detail serializer
    """
    class Meta :
        model = User
        fields = ['id','username','email','first_name','last_name','phone_number','image','address','membre','created_at','wallet_blocked','is_membre','is_admin']
        depth = 1
        




class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = product
        fields = ['id','name_product','price_product','image_product']
       
class ShopSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = Shop
        fields = ['id','name_shop','email_shop','address_shop','products','image_shop']
        depth = 1
        
    def create(self, validated_data):
       

# products=models.ManyToManyField(product)
#     name_shop=models.CharField(max_length=255,default = None,null =True)
#     address_shop=models.CharField(max_length=255 , default = None,null =True)
#     email_shop= models.CharField(max_length=255,default = None,null =True)
#     image_shop


        shop = models.Shop.objects.create(
            name_shop = validated_data["name_shop"],
            email_shop = validated_data["email_shop"],
            address_shop = validated_data["address_shop"],
            
        )

      
        shop.save()
        x=uuid.uuid4().int
        print(x)

        obj = shop_account(wallet_id=x, balance=0,account=shop, is_disabled=False)
        obj.save()

        return shop 
from rest_framework import serializers
from . import models 


class WalletSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Wallet
        fields = ("wallet_id", "is_disabled", "balance","account","maxAmount")
        extra_kwargs = {
            "wallet_id": {
                "read_only": True
            },

            # "is_disabled": {
            #     "read_only": True
            # },

            "balance": {
                "read_only": True
            }
        }


class TransactionHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Transaction
        fields = ("transaction_id", "amount", "timestamp", "to", "type","account")
        depth = 1
  
        extra_kwargs = {
            "transaction_id": {
                "read_only": True
            },

            "amount": {
                "read_only": True
            }, 

            "timestamp": {
                "read_only": True
            },

            "to": {
                "read_only": True 
            }
        }

class TransactionHistoryShopSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.TransactionShop
        fields = ("id","transaction_id", "amount", "timestamp", "to", "type","account","product")
        depth = 2
  
        extra_kwargs = {
            "transaction_id": {
                "read_only": True
            },

            "amount": {
                "read_only": True
            }, 

            "timestamp": {
                "read_only": True
            }, 

            "to": {
                "read_only": True 
            },
            "product" : {
                "read_only": True 
            }
        }
                

class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Payment
        fields = ("to_acct", "amount", )
class PaymentNFCSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.article_vendues
        fields = ["code_NFC",]

class TransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Payment
        fields = ("to_acct", "amount", )
        
        

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer

from rest_framework_simplejwt.tokens import RefreshToken

class TokenObtainLifetimeSerializer(TokenObtainPairSerializer):

    def validate(self, attrs):
        data = super().validate(attrs)
        refresh = self.get_token(self.user)
        data['lifetime'] = int(refresh.access_token.lifetime.total_seconds())
        data.update({'is_admin': self.user.is_admin})
        data.update({'wallet_blocked': self.user.wallet_blocked})
        data.update({'id': self.user.id})
        return data


class TokenRefreshLifetimeSerializer(TokenRefreshSerializer):

    def validate(self, attrs):
        data = super().validate(attrs)
        refresh = RefreshToken(attrs['refresh'])
        data['lifetime'] = int(refresh.access_token.lifetime.total_seconds())
        return data


class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.group
        fields = ("user", "id_groupe","is_superuser","is_member" )

# class group(models.Model):
#     user = models.ForeignKey(User,on_delete=models.CASCADE)
#     id_groupe = models.CharField(max_length=4, validators=[MinLengthValidator(4), MaxLengthValidator(4)], default=generate_groupe_id, unique=True)
#     is_superuser = models.BooleanField(default = False)
#     is_member = models.BooleanField(default =False)

class BlockedProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Blocked_Product
        fields = ("product","user","blocked")



class UpdateProductStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = Blocked_Product
        fields = ["blocked"]
class updateWalletStatusSerializer(serializers.ModelSerializer):
    class Meta  : 
        model = Wallet
        fields = ["is_disabled"]

class ListProductSerializer(serializers.ModelSerializer):
    class Meta  : 
        model = list_product
        fields = ('id','user','product','shop','total')
        depth = 1