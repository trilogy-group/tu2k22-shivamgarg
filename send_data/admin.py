from django.contrib import admin
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
# Register your models here.

class MyAccountManager(BaseUserManager):

    def create_superuser(self, email, name, password):
        user = self.create_user(
            email=self.normalize_email(email),
            password=password,
            username=name,
        )
    
        user = self.create_user(username=username,
        email=self.normalize_email(email),
        password=password,)
        user.is_admin =True
        user.is_staff =True
        user.is_superuser=True
        user.save(using=self._db)
        return user
