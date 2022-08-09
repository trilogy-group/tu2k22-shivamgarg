from dataclasses import fields
from rest_framework import serializers
# from django.contrib.auth.models import User
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password
from .models import *

def validate_decimals(value):
    try:
        return round(float(value), 2)
    except:
        raise ValidationError(
            _('%(value)s is not an integer or a float  number'),
            params={'value': value},
        )


#Serializer to Get user info
class UserSerializer(serializers.ModelSerializer):
    # name = serializers.CharField(source='username')
    
    class Meta:
        model = MyUser
        fields = ['id', 'name', 'email']


#Serializer to Get user detail
class UserDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['available_funds', 'blocked_funds']


#Serializer to Register User
class RegisterSerializer(serializers.ModelSerializer):
    name = serializers.CharField(required=True)
    email = serializers.EmailField(
    required=True,
    validators=[UniqueValidator(queryset=MyUser.objects.all())]
    )
    password = serializers.CharField(
    write_only=True, required=True, validators=[validate_password])
    class Meta:
        model = MyUser
        fields = ('name', 'password', 'email')
    def create(self, validated_data):
        user = MyUser.objects.create(
            name=validated_data['name'],
            email=validated_data['email'],
            first_name='',
            last_name=''
        )
        user.set_password(validated_data['password'])
        user.save()
        return user


#Serializer for sector
class SectorSerializer(serializers.ModelSerializer):
    name = serializers.CharField(required=True)
    description = serializers.CharField(required=False)
    class Meta:
        model = Sectors
        fields = ['id', 'name', 'description']


#Serializer for sector
class SectorPatchSerializer(serializers.ModelSerializer):
    name = serializers.CharField(required=False)
    description = serializers.CharField(required=False)
    class Meta:
        model = Sectors
        fields = ['id', 'name', 'description']


#Serializer for stock
class StockSerializer(serializers.ModelSerializer):
    price = serializers.FloatField(validators=[validate_decimals])
    class Meta:
        model = Stocks
        fields = ['id', 'sector', 'name', 'total_volume', 'unallocated', 'price']


#Serializer for order
class OrderSerializer(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(input_formats='%b %d %Y %H:%M:%S', required=False)
    updated_at = serializers.DateTimeField(input_formats='%b %d %Y %H:%M:%S', required=False)
    class Meta:
        model = Orders
        fields = ["id", "user", "stock", "bid_price", "type", "status", "bid_volume", "executed_volume", "created_at", "updated_at"]


#Serializer for market
class MarketSerializer(serializers.ModelSerializer):
    class Meta:
        model = Market_day
        fields = '__all__'


#Serializer for ohlcv
class OhlcvSerializer(serializers.ModelSerializer):
    class Meta:
        model = Ohlcv
        fields = ['day', 'stock', 'open', 'low', 'high', 'close', 'volume']