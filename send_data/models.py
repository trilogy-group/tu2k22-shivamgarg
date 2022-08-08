import email
from django.db import models
from django.contrib.auth.models import AbstractUser

class MyUser(AbstractUser):
    username = None
    name = models.CharField(max_length=100)
    email = models.EmailField(max_length=100, unique= True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = [ 'name', 'password']
    
    def __str__(self):
        return self.name

class Users(models.Model):
    user_id = models.OneToOneField(MyUser, on_delete=models.CASCADE)
    available_funds = models.FloatField()
    blocked_funds = models.FloatField()
    
    def __str__(self):
        return self.name


class Sectors(models.Model):
    name = models.CharField(max_length=50)
    description = models.CharField(max_length=200)


class Stocks(models.Model):
    name = models.CharField(max_length=20)
    total_volume = models.IntegerField()
    unallocated = models.IntegerField()
    price = models.FloatField()
    sector = models.ForeignKey(Sectors, on_delete=models.CASCADE)


class Holdings(models.Model):
    user = models.ForeignKey(MyUser, on_delete=models.CASCADE)
    stock = models.ForeignKey(Stocks, on_delete=models.CASCADE)
    volume = models.IntegerField()
    bid_price = models.FloatField()
    bought_on = models.DateField()


class Market_day(models.Model):
    day = models.IntegerField()
    status = models.CharField(max_length=10)


class Ohlcv(models.Model):
    day = models.IntegerField()
    stock = models.ForeignKey(Stocks, on_delete=models.CASCADE)
    open = models.FloatField()
    high = models.FloatField()
    low = models.FloatField()
    close = models.FloatField()
    volume = models.IntegerField()
    market = models.ForeignKey(Market_day, on_delete=models.CASCADE)


class Orders(models.Model):
    user = models.ForeignKey(MyUser, on_delete=models.CASCADE)
    stock = models.ForeignKey(Stocks, on_delete=models.CASCADE)
    bid_price = models.FloatField()
    type = models.CharField(max_length=4)
    created_on = models.DateTimeField(auto_now=True)
    updated_on = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20)
    bid_volume = models.IntegerField()
    executed_volume = models.IntegerField()
