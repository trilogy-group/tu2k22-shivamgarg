from django.apps import AppConfig
# from opentelemetry import trace

from random import randint
from flask import Flask, request

# tracer = trace.get_tracer(__name__)

# app = Flask(__name__)



class SendDataConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'send_data'