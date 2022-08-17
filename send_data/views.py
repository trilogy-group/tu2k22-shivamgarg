from random import uniform
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
from django.db.models import Sum, Avg, F

from djoser import signals, utils
from djoser.compat import get_user_email
from djoser.conf import settings
# from opentelemetry import trace, metrics

from flask import Flask, request

# Acquire a tracer
# tracer = trace.get_tracer(__name__)
# meter = metrics.get_meter(__name__)

# app = Flask(__name__)


class IsOwnerOrReadOnlyNote(BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in SAFE_METHODS:
            return True

        return obj.author == request.user

# @app.route("/api/v1/users/profile")
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
            "available_funds": '{:.2f}'.format(serializer2.data['available_funds']),
            "blocked_funds": '{:.2f}'.format(serializer2.data['blocked_funds']),
        }
        return Response(returnData)

    def patch(self, request, format=None):       
    
        try:
            user_id = request.user.id
        except:            
            return Response({"detail":"Authentication credentials were not provided."}, status=status.HTTP_401_UNAUTHORIZED)
        user = MyUser.objects.get(id=user_id)
        user.is_superuser = 1
        user.save()
        serializer = UserSerializer(user)
        returnData = serializer.data
        returnData['is_superuser'] = user.is_superuser
        return Response(returnData, status=status.HTTP_200_OK)

        
class UserAdminAPI(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def patch(self, request, format=None):       
    
        try:
            user_id = request.user.id
        except:            
            return Response({"detail":"Authentication credentials were not provided."}, status=status.HTTP_401_UNAUTHORIZED)
        user = MyUser.objects.get(id=user_id)
        user.is_superuser = 1
        user.save()
        serializer = UserSerializer(user)
        returnData = serializer.data
        returnData['is_superuser'] = user.is_superuser
        return Response(returnData, status=status.HTTP_200_OK)


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
        detail = Users(user_id=obj, available_funds=400000, blocked_funds=0)
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


# @app.route("/api/v1/sectors")
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
        # with tracer.start_as_current_span("getSectors") as getSectors:
            sector = Sectors.objects.all()
            serializer = SectorSerializer(sector, many=True)
            
            return Response(serializer.data)

    def post(self, request, format=None):
        # with tracer.start_as_current_span("postSectors") as postSectors:
            user_id = request.user.id
            user = MyUser.objects.get(pk=user_id)
            if user.is_superuser == 1:
                serializer = SectorSerializer(data=request.data)
                
                if serializer.is_valid(raise_exception=True):
                    serializer.save()
                    return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                return Response({"detail":"Unauthorized to create new sector."}, status=status.HTTP_401_UNAUTHORIZED)                


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
        for each in serializer.data:
            value = each['price'] * uniform(0.5, 1.5)
            each['price'] = '{:.2f}'.format(value)
            update_stock = Stocks.objects.get(pk=each['id'])
            update_stock.price = round(value, 2)
            update_stock.save()

        return Response(serializer.data)

    def post(self, request, format=None):
        user_id = request.user.id
        user = MyUser.objects.get(pk=user_id)
        if user.is_superuser == 1:
            serializer = StockSerializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                returndata = serializer.data
                value = returndata['price']
                returndata['price'] = '{:.2f}'.format(value)
                return Response(returndata, status=status.HTTP_201_CREATED)
        else:
            return Response({"detail":"Unauthorized to create new stock."}, status=status.HTTP_401_UNAUTHORIZED)                


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
        returndata = serializer.data
        value = returndata['price']
        returndata['price'] = '{:.2f}'.format(value)
        return Response(returndata)


class OrderList(APIView):
    """
    List all orders, or create a new order.
    """
    permission_classes = [
        IsAuthenticated,
    ]
    authentication_classes = [
        TokenAuthentication,
    ]
    def get(self, request, format=None):
        user_id = request.user.id
        Order = Orders.objects.filter(user=user_id)
        serializer = OrderSerializer(Order, many=True)
        for each in serializer.data:
            value = each['bid_price']
            each['bid_price'] = '{:.2f}'.format(value)
        return Response(serializer.data)

    def post(self, request, format=None):
        try:
            market_status = Market_day.objects.filter().latest('day').status
            if market_status == "CLOSE":
                return Response(status=status.HTTP_403_FORBIDDEN)
        except:
            Market_day.objects.create(day=1, status="OPEN")

        user_id = request.user.id
        newPost = request.data
        newPost['user'] = user_id
        newPost['status'] = 'PENDING'
        newPost['executed_volume'] = 0
        serializer = OrderSerializer(data=request.data)
        
        if newPost['type'] == 'BUY':
            sufficient_fund = float(newPost['bid_price']) * float(newPost['bid_volume'])
            userdata = Users.objects.get(user_id=user_id)
            available_fund = userdata.available_funds - userdata.blocked_funds
            if available_fund < sufficient_fund:
                err = {"non_field_errors":["Insufficient Wallet Balance"]}
                return Response(err, status=status.HTTP_400_BAD_REQUEST)
            block_fund = {
                "blocked_funds": userdata.blocked_funds + sufficient_fund,
                "available_funds": userdata.available_funds
            }
            userSerializer = UserDetailSerializer(userdata, data=block_fund)
            if userSerializer.is_valid(raise_exception=True):
                userSerializer.save()
        else:
            sufficient_stock = float(newPost['bid_volume'])
            available_stock = 0
            # try:
            holding_stock = Holdings.objects.filter(user=user_id, stock=newPost['stock']).aggregate(Sum('volume'))
            if holding_stock['volume__sum']:
                available_stock = holding_stock['volume__sum']
                pending_sell = Orders.objects.filter(user=user_id, stock=newPost['stock'], status="PENDING", type="SELL").aggregate(volume=Sum(F('bid_volume') - F('executed_volume')))
                if pending_sell['volume']:
                    available_stock -= pending_sell['volume']
            if available_stock < sufficient_stock:
                err = {"non_field_errors":["Insufficient Stock Holdings"]}
                return Response(err, status=status.HTTP_400_BAD_REQUEST)
            # except:
            #     err = {"non_field_errors":["Insufficient Stock Holdings"]}
            #     return Response(err, status=status.HTTP_400_BAD_REQUEST)

        if serializer.is_valid():
            serializer.save()
            returndata = serializer.data
            value = returndata['bid_price']
            returndata['bid_price'] = '{:.2f}'.format(value)
            return Response(returndata, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class OrderDetail(APIView):
    """
    Retrieve a order instance.
    """
    permission_classes = [
        IsAuthenticated,
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
        remain_volume = Order.bid_volume - Order.executed_volume
        user_id = request.user.id
        userdata = Users.objects.get(user_id=user_id)
        userdata.blocked_funds -= remain_volume * Order.bid_price
        userdata.save()

        Order.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class OrderMatch(APIView):
    permission_classes = [
        IsAuthenticated,
    ]
    authentication_classes = [
        TokenAuthentication,
    ]
    def post(self, request, format=None):
        # Sort all order of type “BUY” in  descending order
        buying_orders = Orders.objects.filter(type="BUY", status="PENDING").order_by('-bid_price').all()
        markets = Market_day.objects
        if markets.exists():
            market = markets.filter().latest('day')
            day = market.day
        else:
            market = Market_day.objects.create(day=1, status="OPEN")
            day = 1
        # Matching
        for buy_order in buying_orders:
            buy_bid_volume = buy_order.bid_volume
            buy_bid_price = buy_order.bid_price
            # Sort all order of type “SELL” in ascending order
            selling_orders = Orders.objects.filter(type="SELL", stock=buy_order.stock, status="PENDING").all().order_by('bid_price')
            for sell_order in selling_orders:
                remain_volume = buy_bid_volume - buy_order.executed_volume
                available_volume = sell_order.bid_volume - sell_order.executed_volume
                sell_bid_price = sell_order.bid_price
                # buy_bid_price >= Sell_bid_price can buy
                # remain_volume and avaiable_volume > 0 can buy
                if buy_bid_price < sell_bid_price or remain_volume == 0 or available_volume == 0:
                    continue
                # Latest bidder dictates the price of the transaction
                if buy_order.created_at > sell_order.created_at:
                    transaction_price = buy_bid_price
                else:
                    transaction_price = sell_bid_price
                # If a partial transaction occurs
                if remain_volume > available_volume:
                    transaction_volumn = available_volume
                else:
                    transaction_volumn = remain_volume

                # Transaction
                transaction_fund = transaction_price * transaction_volumn
                
                sell_order.executed_volume += transaction_volumn
                if transaction_volumn == available_volume:
                    sell_order.status = "COMPLETED"
                sell_order.save()
                sell_user = Users.objects.get(user_id=sell_order.user)
                sell_user.available_funds += transaction_fund
                sell_user.save()
                ### decrease holdings
                selling_list = Holdings.objects.filter(user=sell_order.user, stock=sell_order.stock).all()
                discount_amount = transaction_volumn
                for selling in selling_list:
                    if discount_amount > selling.volume:
                        discount_amount -= selling.volume
                        selling.volume = 0                        
                        selling.save()
                        continue
                    else:
                        selling.volume -= discount_amount
                        selling.save()
                        discount_amount = 0
                        break
                ### increase ohlcv
                ohlcvs = Ohlcv.objects.filter(day=market.day, stock=sell_order.stock.id)
                if ohlcvs.exists():
                    ohlcv = ohlcvs.first()
                    ohlcv.volume += int(transaction_volumn)
                    ohlcv.save()
                else:
                    Ohlcv.objects.create(
                        day = day,
                        stock = sell_order.stock,
                        open = 0,
                        high = 0,
                        low = 0,
                        close = 0,
                        volume = transaction_volumn,
                        market = market
                    )
                
                buy_order.executed_volume += transaction_volumn
                buy_user = Users.objects.get(user_id=buy_order.user)
                buy_user.available_funds -= transaction_fund
                buy_user.blocked_funds -= buy_bid_price * transaction_volumn
                buy_user.save()
                Holdings.objects.create(user=buy_order.user, stock=buy_order.stock, volume=transaction_volumn, bid_price=transaction_price, bought_on=day)

            if buy_order.executed_volume == buy_bid_volume:
                buy_order.status = "COMPLETED"
                buy_order.save()
                continue
            
            stock = Stocks.objects.get(pk=buy_order.stock.id)
            remain_volume = buy_bid_volume - buy_order.executed_volume
            available_volume = stock.unallocated
            # buy_bid_price >= Sell_bid_price can buy
            # remain_volume and avaiable_volume > 0 can buy
            if buy_bid_price < stock.price or remain_volume == 0 or available_volume == 0:
                buy_order.save()
                continue
            # Latest bidder dictates the price of the transaction
            transaction_price = buy_bid_price
            # If a partial transaction occurs
            if remain_volume > available_volume:
                transaction_volumn = available_volume
            else:
                transaction_volumn = remain_volume

            # Transaction
            transaction_fund = transaction_price * transaction_volumn
            
            stock.unallocated -= transaction_volumn  
            stock.price = buy_bid_price  
            stock.save()
                
            buy_order.executed_volume += transaction_volumn
            buy_user = Users.objects.get(user_id=buy_order.user)
            buy_user.available_funds -= transaction_fund
            buy_user.blocked_funds -= buy_bid_price * transaction_volumn
            buy_user.save()
            Holdings.objects.create(user=buy_order.user, stock=buy_order.stock, volume=transaction_volumn, bid_price=transaction_price, bought_on=day)

            if transaction_volumn == remain_volume:
                buy_order.status = "COMPLETED"
                
            buy_order.save()
        return Response({"message":"Orders Executed Successfully!"})
                


class GetHolding(APIView):
    def get(self, request, format=None):
        user_id = request.user.id
        holding_list = Holdings.objects.filter(user=user_id)
        possessed = holding_list.values('stock').annotate(avg_investment=Sum(F('volume') * F('bid_price')), total_volume=Sum('volume'))
        investment = 0
        current_value = 0
        posessed_data = []
        for each in possessed:
            stock = Stocks.objects.get(pk=each['stock'])
            new_row = {
                'id': stock.id,
                'name': stock.name,
                'avg_bid_price': '{:.2f}'.format(each['avg_investment'] / each['total_volume']),
                'total_volume': int(each['total_volume'])
            }
            investment += each['avg_investment']
            current_value += each['total_volume'] * stock.price
            posessed_data.append(new_row)
        
        data = {
            'investment': '{:.2f}'.format(investment),
            'current_value': '{:.2f}'.format(current_value),
            'stocks_possessed': posessed_data
        }
        
        return Response(data)

        
class OhlcvDetail(APIView):
    """
    Retrieve a ohlcv instance.
    """
    def get(self, request, format=None):
        day = int(request.GET['day'])
        if day == 0:
            returnData = [
                {
                    "day": 0,
                    "stock": "string",
                    "open": "100.00",
                    "low": "100.00",
                    "high": "100.00",
                    "close": "100.00",
                    "volume": 100
                }
            ]
            return Response(returnData)
        try:
            market = Market_day.objects.get(day=day)
        except:
            return Response(status=status.HTTP_404_NOT_FOUND)
        stock_list = Stocks.objects.all()
        returnData = []
        for stock in stock_list:
            ohlcv = Ohlcv.objects.filter(market=market, stock=stock)
            if ohlcv.exists():
                serializer = OhlcvSerializer(ohlcv.first())
                fixed_data = {
                    'day': serializer.data['day'],
                    'stock': Stocks.objects.get(pk=serializer.data['stock']).name,
                    'open': '{:.2f}'.format(serializer.data['open']),
                    'high': '{:.2f}'.format(serializer.data['high']),
                    'low': '{:.2f}'.format(serializer.data['low']),
                    'close': '{:.2f}'.format(serializer.data['close']),
                    'volume': serializer.data['volume']
                }
                returnData.append(fixed_data)
            else:
                returnData.append({
                    'day': day,
                    'stock': stock.name,
                    'open': '-1.00',
                    'high': '-1.00',
                    'low': '-1.00',
                    'close': '-1.00',
                    'volume': 0
                })
        return Response(returnData)


class OpenMarket(APIView):
    permission_classes = [
        IsAuthenticated,
    ]
    authentication_classes = [
        TokenAuthentication,
    ]
    def post(self, request, format=None):
        market = Market_day.objects.filter()
        if market.exists():
            day = market.latest('day').day + 1
        else:
            day = 1
        data = {
            "status": "OPEN",
            "day": day
            }
        serializer = MarketSerializer(data=data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
        return Response(status=status.HTTP_204_NO_CONTENT)


class CloseMarket(APIView):
    permission_classes = [
        IsAuthenticated,
    ]
    authentication_classes = [
        TokenAuthentication,
    ]
    def post(self, request, format=None):
        markets = Market_day.objects
        if markets.exists():
            market = markets.latest('day')
            market.status = "CLOSE"
            market.save()
        else:
            market = Market_day.objects.create(day=1, status="CLOSE")

        stock_list = Stocks.objects.all()
        for stock in stock_list:
            holding_list = Holdings.objects.filter(stock=stock, bought_on=market.day)
            if holding_list.exists():
                open_price = holding_list.order_by('id').first().bid_price
                close_price = holding_list.order_by('-id').first().bid_price
                high_price = holding_list.order_by('-bid_price').first().bid_price
                low_price = holding_list.order_by('bid_price').first().bid_price
                volume = holding_list.aggregate(Sum('volume'))['volume__sum']
                
                ohlcvs = Ohlcv.objects.filter(day=market.day,stock=stock.id)
                if ohlcvs.exists():
                    ohlcv = ohlcvs.first()
                    ohlcv.open = open_price
                    ohlcv.high = high_price
                    ohlcv.low = low_price
                    ohlcv.close = close_price
                    ohlcv.volume += volume
                    ohlcv.save()
                else:
                    Ohlcv.objects.create(
                        day=market.day,
                        stock=stock,
                        open=open_price,
                        high=high_price,
                        low=low_price,
                        close=close_price,
                        volume=volume,
                        market=market
                    )

        return Response(status=status.HTTP_204_NO_CONTENT)