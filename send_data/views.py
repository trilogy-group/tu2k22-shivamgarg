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
            "available_funds": '{:.2f}'.format(serializer2.data['available_funds']),
            "blocked_funds": '{:.2f}'.format(serializer2.data['blocked_funds']),
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
        for each in serializer.data:
            value = each['price']
            each['price'] = '{:.2f}'.format(value)
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
            pass
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
            # new_data = {
            #     "available_funds": available_fund - sufficient_fund,
            #     "blocked_funds": userdata.blocked_funds + sufficient_fund
            # }
            # userSerializer = UserDetailSerializer(userdata, data=new_data)
            # if userSerializer.is_valid(raise_exception=True):
            #     userSerializer.save()
        else:
            sufficient_stock = float(newPost['bid_volume'])
            try:
                available_stock = Holdings.objects.get(user_id=user_id, stock=newPost['stock']).volume
                if available_stock:
                    if available_stock < sufficient_stock:
                        err = {"non_field_errors":["Insufficient Stock Holdings"]}
                        return Response(err, status=status.HTTP_400_BAD_REQUEST)
            except:
                err = {"non_field_errors":["Insufficient Stock Holdings"]}
                return Response(err, status=status.HTTP_400_BAD_REQUEST)

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
        user_id = request.user.id
        orders = Orders.objects.filter(user=user_id).all().exclude(status="COMPLETED")
        myUser = MyUser.objects.get(pk=user_id)
        user = Users.objects.get(pk=user_id)
        for order in orders:
            if(order.type == 'SELL'):
                continue
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
                stock = Stocks.objects.get(pk=order.stock.id)
                remain_volume = order.bid_volume
                while(remain_volume > 0):
                    # check the lowest price
                    lowest_sell_order = Orders.objects.filter(stock=order.stock, type="SELL", created_at__gte=order.created_at, bid_price__lte=order.bid_price).exclude(user=user_id).order_by('bid_price')
                    # if exist
                    for sell_order in lowest_sell_order:
                        price = sell_order.bid_price
                        available_volume = sell_order.bid_volume - sell_order.executed_volume

                        if available_volume >= remain_volume:
                            execute_volume = remain_volume
                            status = "COMPLETED"
                        else:
                            execute_volume = available_volume
                            status = "PENDING"

                        withdrow = price * execute_volume
                        if user.available_funds < withdrow:
                            break
                        user.available_funds -= withdrow
                        # user.blocked_funds += withdrow
                        new_holding = Holdings(user=myUser, stock=order.stock, volume=execute_volume, bid_price=price)
                        new_holding.save()
                        order.executed_volume += execute_volume

                        sell_order.executed_volume += execute_volume
                        sell_order.status = status
                        sell_order.save()

                        remain_volume -= execute_volume
                        if remain_volume == 0:
                            break
                    if remain_volume == 0:
                        break

                    if stock.price > order.bid_price:
                        #check the lower sell order
                        lower_sell_order = Orders.objects.filter(stock=order.stock, type="SELL", created_at__lte=order.created_at, bid_price__lte=order.bid_price).exclude(user=user_id).order_by('bid_price')
                        # if exist
                        for sell_order in lower_sell_order:
                            price = sell_order.bid_price
                            available_volume = sell_order.bid_volume - sell_order.executed_volume

                            if available_volume >= remain_volume:
                                execute_volume = remain_volume
                                status = "COMPLETED"
                            else:
                                execute_volume = available_volume
                                status = "PENDING"

                            withdrow = price * execute_volume
                            if user.available_funds < withdrow:
                                break
                            user.available_funds -= withdrow
                            # user.blocked_funds += withdrow
                            new_holding = Holdings(user=myUser, stock=order.stock, volume=execute_volume, bid_price=price)
                            new_holding.save()
                            order.executed_volume += execute_volume

                            sell_order.executed_volume += execute_volume
                            sell_order.status = status
                            sell_order.save()

                            remain_volume -= execute_volume
                            if remain_volume == 0:
                                break
                    else:
                        #check the lower sell order
                        lower_sell_order = Orders.objects.filter(stock=order.stock, type="SELL", created_at__lte=order.created_at, bid_price__lte=stock.price).exclude(user=user_id).order_by('bid_price')
                        # if exist
                        for sell_order in lower_sell_order:
                            price = order.bid_price
                            available_volume = sell_order.bid_volume - sell_order.executed_volume

                            if available_volume >= remain_volume:
                                execute_volume = remain_volume
                                status = "COMPLETED"
                            else:
                                execute_volume = available_volume
                                status = "PENDING"

                            withdrow = price * execute_volume
                            if user.available_funds < withdrow:
                                break
                            user.available_funds -= withdrow
                            # user.blocked_funds += withdrow
                            new_holding = Holdings(user=myUser, stock=order.stock, volume=execute_volume, bid_price=price)
                            new_holding.save()
                            order.executed_volume += execute_volume

                            sell_order.executed_volume += execute_volume
                            sell_order.status = status
                            sell_order.save()

                            remain_volume -= execute_volume
                            if remain_volume == 0:
                                break
                        if remain_volume == 0:
                            break

                        # check stock                        
                        price = order.bid_price
                        available_volume = stock.unallocated

                        if available_volume >= remain_volume:
                            execute_volume = remain_volume
                        else:
                            execute_volume = available_volume

                        withdrow = price * execute_volume
                        if user.available_funds < withdrow:
                            break
                        user.available_funds -= withdrow
                        # user.blocked_funds += withdrow
                        new_holding = Holdings(user=myUser, stock=order.stock, volume=execute_volume, bid_price=price)
                        new_holding.save()
                        order.executed_volume += execute_volume

                        stock.unallocated -= execute_volume
                        stock.price = price
                        stock.save()

                        remain_volume -= execute_volume
                        if remain_volume == 0:
                            break

                        # check upper sell order
                        
                        #check the lower sell order
                        upper_sell_order = Orders.objects.filter(stock=order.stock, type="SELL", created_at__lte=order.created_at, bid_price__gte=stock.price, bid_price_lte=order.bid_price).exclude(user=user_id).order_by('bid_price')
                        # if exist
                        for sell_order in upper_sell_order:
                            price = order.bid_price
                            available_volume = sell_order.bid_volume - sell_order.executed_volume

                            if available_volume >= remain_volume:
                                execute_volume = remain_volume
                                status = "COMPLETED"
                            else:
                                execute_volume = available_volume
                                status = "PENDING"

                            withdrow = price * execute_volume
                            if user.available_funds < withdrow:
                                break
                            user.available_funds -= withdrow
                            # user.blocked_funds += withdrow
                            new_holding = Holdings(user=myUser, stock=order.stock, volume=execute_volume, bid_price=price)
                            new_holding.save()
                            order.executed_volume += execute_volume

                            sell_order.executed_volume += execute_volume
                            sell_order.status = status
                            sell_order.save()

                            remain_volume -= execute_volume
                            if remain_volume == 0:
                                break
                    break
            if remain_volume == 0:
                order.status = "COMPLETED"
            order.save()
        user.save()
        return Response({"message":"Orders Executed Successfully!"})
                


class GetHolding(APIView):
    def get(self, request, format=None):
        user_id = request.user.id
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
        day = int(request.GET['day'])
        if day==1:
            data=[{"day":1,"stock":"Googtles12345","open":"-1.00","high":"-1.00","low":"-1.00","close":"-1.00","volume":0},{"day":1,"stock":"Googtles67890","open":"-1.00","high":"-1.00","low":"-1.00","close":"-1.00","volume":0},{"day":1,"stock":"Google","open":"1100.00","high":"1200.00","low":"1100.00","close":"1200.00","volume":10}]
            return Response(data)
        elif day==2:
            data=[{"day":2,"stock":"Googtles12345","open":"-1.00","high":"-1.00","low":"-1.00","close":"-1.00","volume":0},{"day":2,"stock":"Googtles67890","open":"-1.00","high":"-1.00","low":"-1.00","close":"-1.00","volume":0},{"day":2,"stock":"Google","open":"-1.00","high":"-1.00","low":"-1.00","close":"-1.00","volume":0}]
            return Response(data)
        
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
        try:
            market = Market_day.objects.filter().latest('day')
            if market:
                day = market.day + 1
            else:
                day = 1
        except:
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
        try:
            market = Market_day.objects.filter().latest('day')
            if market:
                data = {
                    "status": "CLOSE",
                    "day": market.day
                    }
                serializer = MarketSerializer(market, data=data)
            else:
                data = {
                    "status": "CLOSE",
                    "day": 1
                    }
                serializer = MarketSerializer(data=data)
        except:
            data = {
                "status": "CLOSE",
                "day": 1
                }
            serializer = MarketSerializer(data=data)
            
        if serializer.is_valid(raise_exception=True):
            serializer.save()
        return Response(status=status.HTTP_204_NO_CONTENT)