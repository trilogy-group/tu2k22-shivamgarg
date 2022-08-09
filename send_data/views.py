from urllib import response
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
from django.http import Http404
from django.utils import timezone
from django.db.models import Sum, Avg

from djoser import signals, utils
from djoser.compat import get_user_email
from djoser.conf import settings


class IsOwnerOrReadOnlyNote(BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in SAFE_METHODS:
            return True

        return obj.author == request.user



# Class based view to Get User Details using Token Authentication
class UserDetailAPI(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    def get(self,request,*args,**kwargs):
        try:
            user_id = request.user.id
        except:            
            return Response({"detail":"Authentication credentials were not provided."}, status=status.HTTP_401_UNAUTHORIZED)
        user = MyUser.objects.get(id=user_id)
        serializer1 = UserSerializer(user)
        userdata = Users.objects.get(user_id=user_id)
        serializer2 = UserDetailSerializer(userdata)
        returnData = {
            "id": serializer1.data['id'],
            "name": serializer1.data['name'],
            "email": serializer1.data['email'],
            "available_funds": serializer2.data['available_funds'],
            "blocked_funds": serializer2.data['blocked_funds'],
        }
        return Response(returnData)


#Class based view to register user
class RegisterUserAPIView(generics.CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer
    def post(self, request, *args, **kwargs):
        # params = request.data
        # keys = params.keys()
        # return_error = {}
        # if 'email' not in keys or params['email'] == '':
        #     return_error.apppend({"email":["This field is required."]})
        #     return Response({"email":["This field is required."]}, status=status.HTTP_400_BAD_REQUEST)
        # elif 'password' not in keys or params['password'] == '':
        #     return Response({"password":["This field is required."]}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            obj = serializer.save()
        # else:
        #     return Response(serializer.errors, status=status.HTTP_401_UNAUTHORIZED)
        headers = self.get_success_headers(serializer.data)
        detail = Users(user_id=obj, available_funds=5000, blocked_funds=0)
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
    model = MyUser

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


class SectorList(APIView):
    """
    List all sectors, or create a new sector.
    """
    permission_classes = [
        IsAuthenticatedOrReadOnly,
    ]
    authentication_classes = [
        TokenAuthentication,
    ]
    def get(self, request, format=None):
        sector = Sectors.objects.all()
        serializer = SectorSerializer(sector, many=True)
        return Response(serializer.data)

    def post(self, request, format=None):
        serializer = SectorSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)


class SectorDetail(APIView):
    """
    Retrieve, update or delete a sector instance.
    """
    permission_classes = [
        IsAuthenticatedOrReadOnly,
    ]
    authentication_classes = [
        TokenAuthentication,
    ]

    def get_object(self, pk):
        try:
            return Sectors.objects.get(pk=pk)
        except Sectors.DoesNotExist:
            raise Http404

    def get(self, request, pk, format=None):
        sector = self.get_object(pk)
        serializer = SectorSerializer(sector)
        return Response(serializer.data)

    def patch(self, request, pk, format=None):
        sector = self.get_object(pk)
        serializer = SectorPatchSerializer(sector, data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data)
        # if serializer.is_valid():
        #     serializer.save()
        #     return Response(serializer.data)
        # return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class StockList(APIView):
    """
    List all stocks, or create a new stock.
    """
    permission_classes = [
        IsAuthenticatedOrReadOnly,
    ]
    authentication_classes = [
        TokenAuthentication,
    ]
    def get(self, request, format=None):
        stock = Stocks.objects.all()
        serializer = StockSerializer(stock, many=True)
        return Response(serializer.data)

    def post(self, request, format=None):
        serializer = StockSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)


class StockDetail(APIView):
    """
    Retrieve, update or delete a stock instance.
    """
    permission_classes = [
        IsAuthenticatedOrReadOnly,
    ]
    authentication_classes = [
        TokenAuthentication,
    ]
    def get_object(self, pk):
        try:
            return Stocks.objects.get(pk=pk)
        except Stocks.DoesNotExist:
            raise Http404

    def get(self, request, pk, format=None):
        Stock = self.get_object(pk)
        serializer = StockSerializer(Stock)
        return Response(serializer.data)


class OrderList(APIView):
    """
    List all orders, or create a new order.
    """
    permission_classes = [
        IsAuthenticatedOrReadOnly,
    ]
    authentication_classes = [
        TokenAuthentication,
    ]
    def get(self, request, format=None):
        Order = Orders.objects.all()
        serializer = OrderSerializer(Order, many=True)
        return Response(serializer.data)

    def post(self, request, format=None):
        user_id = request.user.id
        newPost = request.data
        newPost['user'] = user_id
        newPost['status'] = 'PENDING'
        newPost['executed_volume'] = 0
        serializer = OrderSerializer(data=request.data)
        
        if newPost['type'] == 'BUY':
            sufficient_fund = float(newPost['bid_price']) * float(newPost['bid_volume'])
            userdata = Users.objects.get(user_id=user_id)
            available_fund = userdata.available_funds
            if available_fund < sufficient_fund:
                err = {"non_field_errors":["Insufficient Wallet Balance"]}
                return Response(err, status=status.HTTP_400_BAD_REQUEST)
            new_data = {
                "available_funds": available_fund - sufficient_fund,
                "blocked_funds": userdata.blocked_funds + sufficient_fund
            }
            userSerializer = UserDetailSerializer(userdata, data=new_data)
            if userSerializer.is_valid(raise_exception=True):
                userSerializer.save()
        else:
            sufficient_stock = float(newPost['bid_volume'])
            available_stock = Holdings.objects.get(user_id=user_id, stock=newPost['stock']).volume
            if available_stock:
                if available_stock < sufficient_stock:
                    err = {"non_field_errors":["Insufficient Stock Holdings"]}
                    return Response(err, status=status.HTTP_400_BAD_REQUEST)
            else:
                err = {"non_field_errors":["Insufficient Stock Holdings"]}
                return Response(err, status=status.HTTP_400_BAD_REQUEST)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class OrderDetail(APIView):
    """
    Retrieve a order instance.
    """
    permission_classes = [
        IsAuthenticatedOrReadOnly,
    ]
    authentication_classes = [
        TokenAuthentication,
    ]
    def get_object(self, pk):
        try:
            return Orders.objects.get(pk=pk)
        except Orders.DoesNotExist:
            raise Http404

    def get(self, request, pk, format=None):
        Order = self.get_object(pk)
        serializer = OrderSerializer(Order)
        return Response(serializer.data)


class OrderDelete(APIView):
    """
    Delete a order instance.
    """
    permission_classes = [
        IsAuthenticatedOrReadOnly,
    ]
    authentication_classes = [
        TokenAuthentication,
    ]
    def get_object(self, pk):
        try:
            return Orders.objects.get(pk=pk)
        except Orders.DoesNotExist:
            raise Http404

    def delete(self, request, pk, format=None):
        Order = self.get_object(pk)
        Order.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class OrderMatch(APIView):
    permission_classes = [
        IsAuthenticatedOrReadOnly,
    ]
    authentication_classes = [
        TokenAuthentication,
    ]
    def post(self, request, format=None):
        user_id = Token.objects.get(key=self.request.META.get('HTTP_AUTHORIZATION', None)).user_id
        orders = Orders.objects.filter(user=user_id).all()
        for order in orders:
            if(order.type == 'SELL'):
                current_volume = Holdings.objects.filter(user=user_id).aggregate(investment=Sum('volume'))['investment']
                if current_volume > order.bid_volume:
                    order.executed_volume = order.bid_volume
                    order.save()
                else:
                    new_order = {
                        'bid_price': order.bid_price,
                        'bid_volume': order.bid_volume,
                        'stock': order.stock.id,
                        'type': 'BUY',
                        'user': user_id,
                        'status': 'COMPLETE',
                        'executed_volume': 0
                    }
                    serializer = OrderSerializer(data=new_order)
                    if serializer.is_valid(raise_exception=True):
                        serializer.save()
                        return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                buy_obj = Orders.objects.all().exclude(user=user_id).order_by('bid_price')[0]
                buy_obj.execution_volume = order.bid_volume
                buy_obj.save()
        
        all_order = Orders.objects.filter(user=user_id).all()
        serializer = OrderSerializer(all_order, many=True)
        return Response(serializer.data)
                


class GetHolding(APIView):
    def get(self, request, format=None):
        user_id = Token.objects.get(key=self.request.META.get('HTTP_AUTHORIZATION', None)).user_id
        data = Holdings.objects.filter(user=user_id).aggregate(investment=Sum('volume'), current_value=Sum('bid_price'))
        posessed = Holdings.objects.values('stock').annotate(avg_bid_price=Avg('bid_price'), total_volume=Sum('volume'))
        posessed_data = []
        for each in posessed:
            name = Stocks.objects.get(pk=each['stock']).sector.name
            new_row = {
                'id': each['stock'],
                'name': name,
                'avg_bid_price': each['avg_bid_price'],
                'total_volume': each['total_volume']
            }
            posessed_data.append(new_row)
        
        data['stocks_posessed'] = posessed_data
        
        return Response(data)

        
class OhlcvDetail(APIView):
    """
    Retrieve a ohlcv instance.
    """
    def get(self, request, format=None):
        day = request.GET['day']
        market_id = Market_day.objects.get(day=day).id
        ohlcv = Ohlcv.objects.get(market=market_id)
        serializer = OhlcvSerializer(ohlcv)
        return Response(serializer.data)


class OpenMarket(APIView):
    permission_classes = [
        IsAuthenticated,
    ]
    authentication_classes = [
        TokenAuthentication,
    ]
    def post(self, request, format=None):
        user_id = Token.objects.get(key=self.request.META.get('HTTP_AUTHORIZATION', None)).user_id
        if(user_id):
            day = timezone.now().day
            market = Market_day.objects.get(day=day)
            data = {
                "status": "OPEN",
                "day": day
                }
            serializer = MarketSerializer(market, data=data)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                return Response(serializer.data, status=status.HTTP_204_NO_CONTENT)
        else:
            return Response('You are not authorized for this.')


class CloseMarket(APIView):
    permission_classes = [
        IsAuthenticated,
    ]
    authentication_classes = [
        TokenAuthentication,
    ]
    def post(self, request, format=None):
        user_id = Token.objects.get(key=self.request.META.get('HTTP_AUTHORIZATION', None)).user_id
        if(user_id):
            day = timezone.now().day
            market = Market_day.objects.get(day=day)
            data = {
                "status": "CLOSE",
                "day": day
                }
            serializer = MarketSerializer(market, data=data)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response('You are not authorized for this.')