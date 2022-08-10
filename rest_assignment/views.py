
from django.shortcuts import render, redirect
from django.db.models.query import QuerySet
from django.db.models import Q
from rest_framework import generics, viewsets, permissions
from rest_framework.response import Response
from rest_framework import status
# from .serializers import UserSerializer, UserLoginSerializer, UserLogoutSerializer, \
from .serializers import SectorSerializer, StockSerializer, OrderSerializer, MarketSerializer, OhlcvSerializer, HoldingsSerializer
from .models import users, stocks, sectors, orders, ohlcv, holdings, market_day,User
from rest_framework.permissions import AllowAny, BasePermission, SAFE_METHODS, IsAuthenticated, IsAuthenticatedOrReadOnly
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import *
# from django.contrib.auth.models import User
from rest_framework.authentication import TokenAuthentication
from rest_framework import generics
from .models import *
from rest_framework import status
from rest_framework.authtoken.models import Token

from djoser import signals, utils
from djoser.compat import get_user_email
from djoser.conf import settings






def index(request):
    return redirect('/api/v1/auth/signup/')


def getUsersDetails(request, username):
    getUsersDetails = users.objects.get(name=username)
    return render(request, "userDetails.html", {'getDetails': getUsersDetails})


class UserViewSet(viewsets.ModelViewSet):
    queryset = users.objects.all()
    serializer_class = UserSerializer

    def get_object(self):
        pk = self.kwargs.get('pk')

        if pk == "current":
            return self.request.user

        return super(UserViewSet, self).get_object()


class IsOwnerOrReadOnlyNote(BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in SAFE_METHODS:
            return True
        return obj.author == request.user



class UserDetailAPI(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    def get(self,request,*args,**kwargs):
        try:
            user_id = request.user.id
        except:            
            return Response({"detail":"Authentication credentials were not provided."}, status=status.HTTP_401_UNAUTHORIZED)
        user = User.objects.get(id=user_id)
        serializer1 = UserSerializer(user)
        userdata = users.objects.get(user_id=user_id)
        serializer2 = UserDetailSerializer(userdata)
        returnData = {
            "id": serializer1.data['id'],
            "name": serializer1.data['name'],
            "email": serializer1.data['email'],
            "available_funds": serializer2.data['available_funds'],
            "blocked_funds": serializer2.data['blocked_funds'],
        }
        return Response(returnData)


class RegisterUserAPIView(generics.CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            obj = serializer.save()
        headers = self.get_success_headers(serializer.data)
        detail = users(user_id=obj, available_funds=0, blocked_funds=0)
        detail.save()
        response_data = {
            'id': obj.id
        }
        return Response(response_data, status=status.HTTP_201_CREATED, headers=headers)


class TokenCreateView(utils.ActionViewMixin, generics.GenericAPIView):
    """
    Use this endpoint to obtain user authentication token.
    """

    serializer_class = settings.SERIALIZERS.token_create
    permission_classes = settings.PERMISSIONS.token_create
    model = User

    def _action(self, serializer):
        # self.request.user.name = self.request.data.username
        token = utils.login_user(self.request, serializer.user)
        token_serializer_class = settings.SERIALIZERS.token
        returnData = {
            'token': token_serializer_class(token).data['auth_token']
        }
        return Response(
            data=returnData, status=status.HTTP_200_OK
        )


class TokenDestroyView(APIView):
    """
    Use this endpoint to logout user (remove user authentication token).
    """

    permission_classes = [
        IsAuthenticated,
    ]
    authentication_classes = [
        TokenAuthentication,
    ]
    # permission_classes = settings.PERMISSIONS.token_destroy

    def post(self, request):
        utils.logout_user(request)
        return Response(status=status.HTTP_204_NO_CONTENT)
