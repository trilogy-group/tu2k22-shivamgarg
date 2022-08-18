import email
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

def validate_decimals(value):
    try:
        return round(float(value), 2)
    except:
        raise ValidationError(
            _('%(value)s is not an integer or a float  number'),
            params={'value': value},
        )

class MyUser(AbstractUser):
    username = None
    name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', 'password']
    
    def __str__(self):
        return self.name

class Users(models.Model):
    user_id = models.OneToOneField(MyUser, on_delete=models.CASCADE)
    available_funds = models.FloatField(validators=[validate_decimals])
    blocked_funds = models.FloatField(validators=[validate_decimals])
    
    def __str__(self):
        return self.name


class Sectors(models.Model):
    name = models.CharField(max_length=50)
    description = models.CharField(max_length=200)


class Stocks(models.Model):
    name = models.CharField(max_length=20)
    total_volume = models.IntegerField()
    unallocated = models.IntegerField()
    price = models.FloatField(validators=[validate_decimals])
    sector = models.ForeignKey(Sectors, on_delete=models.CASCADE)


class Stock_news(models.Model):
    stock = models.ForeignKey(Stocks, on_delete=models.CASCADE)
    news = models.TextField()


class Watchlist(models.Model):
    name = models.CharField(max_length=20, unique=False)


class Watchlist_Stock(models.Model):
    watchlist = models.ForeignKey(Watchlist, on_delete=models.CASCADE)
    stock = models.ForeignKey(Stocks, on_delete=models.CASCADE)


class Holdings(models.Model):
    user = models.ForeignKey(MyUser, on_delete=models.CASCADE)
    stock = models.ForeignKey(Stocks, on_delete=models.CASCADE)
    volume = models.IntegerField()
    bid_price = models.FloatField(validators=[validate_decimals])
    bought_on = models.IntegerField()


class Market_day(models.Model):
    day = models.IntegerField()
    status = models.CharField(max_length=10)


class Ohlcv(models.Model):
    day = models.IntegerField()
    stock = models.ForeignKey(Stocks, on_delete=models.CASCADE)
    open = models.FloatField(validators=[validate_decimals])
    high = models.FloatField(validators=[validate_decimals])
    low = models.FloatField(validators=[validate_decimals])
    close = models.FloatField(validators=[validate_decimals])
    volume = models.IntegerField()
    market = models.ForeignKey(Market_day, on_delete=models.CASCADE)


class Orders(models.Model):
    user = models.ForeignKey(MyUser, on_delete=models.CASCADE)
    stock = models.ForeignKey(Stocks, on_delete=models.CASCADE)
    bid_price = models.FloatField(validators=[validate_decimals])
    type = models.CharField(max_length=4)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=20)
    bid_volume = models.IntegerField()
    executed_volume = models.IntegerField()