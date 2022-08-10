from email.policy import default
from typing_extensions import Required
from django.db.models import Q  # for queries
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from .models import users, sectors, stocks, orders, market_day, ohlcv, holdings,User
from django.core.exceptions import ValidationError
from uuid import uuid4
from django.contrib.auth.password_validation import validate_password
from rest_framework import generics, viewsets, permissions,status
from .CV import CustomValidation




class HoldingsSerializer(serializers.ModelSerializer):
    errors = None
    class Meta:
        model = holdings
        fields = '__all__'


class OhlcvSerializer(serializers.ModelSerializer):
    errors = None
    class Meta:
        model = ohlcv
        fields = '__all__'


class MarketSerializer(serializers.ModelSerializer):
    errors = None    
    class Meta:
        model = market_day
        fields = '__all__'


class OrderSerializer(serializers.ModelSerializer):
    errors = None
    class Meta:
        model = orders
        fields = '__all__'


class StockSerializer(serializers.ModelSerializer):
    errors = None
    class Meta:
        model = stocks
        fields = '__all__'


class SectorSerializer(serializers.ModelSerializer):
    errors = None
    class Meta:
        model = sectors
        fields = '__all__'
    

class UserDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = users
        fields = ['available_funds', 'blocked_funds']


class RegisterSerializer(serializers.ModelSerializer):
    name = serializers.CharField(required=True)
    email = serializers.EmailField(
    required=True,
    validators=[UniqueValidator(queryset=User.objects.all())]
    )
    password = serializers.CharField(
    write_only=True, required=True, validators=[validate_password])
    class Meta:
        model = User
        fields = ('name', 'password', 'email')
    
    def create(self, validated_data):
        user = User.objects.create(
            name=validated_data['name'],
            email=validated_data['email'],
            first_name='',
            last_name=''
        )
        user.set_password(validated_data['password'])
        user.save()
        return user

class UserSerializer(serializers.ModelSerializer):
    # name = serializers.CharField(source='username')
    
    class Meta:
        model = User
        fields = ['id', 'name', 'email']

