import imp
from django.urls import path
from .views import *
# from djoser.views import TokenCreateView

urlpatterns = [
    path('auth/signup/', RegisterUserAPIView.as_view()),
    path('auth/login/', TokenCreateView.as_view(), name="login"),
    path('auth/github_login/', TokenCreateView.as_view(), name="github_login"),
    path('auth/logout/', TokenDestroyView.as_view(), name="logout"),
    path('users/profile/', UserDetailAPI.as_view()),
    
    path('sectors/', SectorList.as_view()),
    path('sectors/<int:pk>/', SectorDetail.as_view()),
    
    path('stocks/', StockList.as_view()),
    path('stocks/<int:pk>/', StockDetail.as_view()),
    
    path('orders/', OrderList.as_view()),
    path('orders/<int:pk>/', OrderDetail.as_view()),
    path('orders/<int:pk>/cancel/', OrderDelete.as_view()),
    path('orders/match/', OrderMatch.as_view()),

    path('holdings/', GetHolding.as_view()),
    
    path('market/open/', OpenMarket.as_view()),
    path('market/close/', CloseMarket.as_view()),
    path('market/ohlc/', OhlcvDetail.as_view()),
]
