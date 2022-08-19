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




import django
django.setup()
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view
from random import randrange
from datetime import datetime, timedelta
from multiprocessing import Pool
import urllib
from datetime import datetime
from operator import itemgetter

def process_log(url):
    data = urllib.request.urlopen(url)
    data = data.read().decode('utf-8')
    data = data.split("\r\n")

    output = {}

    for line in data:
        line = line.split(" ")
        timestamp = int(line[1]) // 1000
        time_obj = datetime.utcfromtimestamp(timestamp)
        hour = time_obj.strftime('%H')
        minute = (int(time_obj.strftime('%M')) // 15) * 15

        endMinute = str(minute + 15) if minute + 15 < 60 else "00"
        endHour = hour if endMinute != "00" else str(int(hour) + 1)
        endHour = "00" if endHour == "24" else endHour
        key = (hour + ":" + (str(minute) if minute > 9 else "0" + str(minute))) + "-" + (endHour if len(endHour) > 1 else "0" + endHour) + ":" + endMinute
        order_type = line[2]

        if key in output:
            if order_type in output[key]:
                output[key][order_type] += 1
            else:
                output[key][order_type] = 1
        else:
            output[key] = {}
            output[key][order_type] = 1

    return output

@api_view(["POST"])
def process_logs(request):
    files = request.data.get("logFiles", [])
    print(files)
    p = Pool(int(request.data.get("parallelFileProcessingCount")))
    calculated_logs = p.map(process_log, files)
    output_logs_dict = {}

    notFirst = False
    for log in calculated_logs:
        if notFirst:
            for span in log:
                if span in output_logs_dict:
                    for order_type in log[span]:
                        if order_type in output_logs_dict[span]:
                            output_logs_dict[span][order_type] += log[span][order_type]
                        else:
                            output_logs_dict[span][order_type] = log[span][order_type]
                else:
                    output_logs_dict[span] = log[span]
        else:
            output_logs_dict = log
            notFirst = True

    output_array = []
    for log in output_logs_dict:
        order_details = []
        for order in output_logs_dict[log]:
            order_details.append({
                "order": order,
                "count": output_logs_dict[log][order]
            })
        order_details = sorted(order_details, key=itemgetter('order'), reverse=True)
        output_array.append({
            "timestamp": log,
            "logs": order_details
        })    

    priorities = {}
    first_priority_item = output_array[0]["timestamp"]
    first_priority_item_arr = first_priority_item.split("-")
    first_priority_item_start_arr = first_priority_item_arr[0].split(":")
    hour = int(first_priority_item_start_arr[0])
    minute = int(first_priority_item_start_arr[1])

    first_priority_item_end_arr = first_priority_item_arr[1].split(":")
    endHour = int(first_priority_item_end_arr[0])
    endMinute = int(first_priority_item_end_arr[1])

    priority = 0
    priorities[first_priority_item] = priority
    while priority < 95:
        minute = minute + 15
        hour = hour if minute < 60 else hour + 1
        hour = hour if hour < 24 else 0
        minute = minute if minute < 60 else 0
        endMinute = endMinute + 15
        endHour = endHour if endMinute < 60 else endHour + 1
        endHour = endHour if endHour < 24 else 0
        endMinute = endMinute if endMinute < 60 else 0
        priority = priority + 1

        minuteStr = str(minute) if minute > 0 else "00"
        hourStr = str(hour) if hour > 9 else "0" + str(hour)
        hourStr = "00" if hourStr == "24" else hourStr

        endMinuteStr = str(endMinute) if endMinute > 0 else "00"
        endHourStr = str(endHour) if endHour > 9 else "0" + str(endHour)
        endHourStr = "00" if endHourStr == "24" else endHourStr

        priorities[hourStr + ":" + minuteStr + "-" + endHourStr + ":" + endMinuteStr] = priority
    


    def compare(item1):
        return priorities[item1["timestamp"]]

    output_array = sorted(output_array, key=compare)
    return Response({"response": output_array})

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
        markets = Market_day.objects
        if markets.exists():
            market = markets.filter().latest('day')
        else:
            market = Market_day.objects.create(day=1, status="OPEN")

        stock = Stocks.objects.all()
        serializer = StockSerializer(stock, many=True)
        returnData = serializer.data
        for each in returnData:
            if market.status == "OPEN":
                value = round(each['price'] * uniform(0.9, 1.1), 2)
            else:
                value = each['price']
            each['price'] = '{:.2f}'.format(value)
            update_stock = Stocks.objects.get(pk=each['id'])
            update_stock.price = value
            update_stock.save()
            
            ohlcvs = Ohlcv.objects.filter(day=market.day, stock=update_stock.id)
            if ohlcvs.exists():
                ohlcv = ohlcvs.first()
                ohlcv.high = max(ohlcv.high, update_stock.price)
                ohlcv.low = min(ohlcv.low, update_stock.price)
                ohlcv.close = update_stock.price
                ohlcv.save()
            else:
                previous = Ohlcv.objects.filter(day=market.day-1, stock=update_stock.id)
                if previous.exists():
                    open_price = previous.first().close
                else:
                    open_price = update_stock.price
                Ohlcv.objects.create(
                    day = market.day,
                    stock = update_stock,
                    open = open_price,
                    high = max(open_price, update_stock.price),
                    low = min(open_price, update_stock.price),
                    close = update_stock.price,
                    volume = 0,
                    market = market
                )        

            news = Stock_news.objects.filter(stock=each['id']).all()
            news_data = NewsSerializer(news, many=True).data
            each['news'] = []
            for news_each in news_data:
                each['news'].append(news_each['news'])

        return Response(returnData)

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
        news = Stock_news.objects.filter(stock=Stock.id).all()
        news_data = NewsSerializer(news, many=True).data
        returndata['news'] = []
        for news_each in news_data:
            returndata['news'].append(news_each['news'])
        return Response(returndata)

    def patch(self, request, pk, format=None):
        Stock = self.get_object(pk)
        data = request.data
        data['stock'] = Stock.id
        serializer = NewsSerializer(data=data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data)


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
                    transaction_volume = available_volume
                else:
                    transaction_volume = remain_volume

                # Transaction
                transaction_fund = transaction_price * transaction_volume
                
                sell_order.executed_volume += transaction_volume
                if transaction_volume == available_volume:
                    sell_order.status = "COMPLETED"
                sell_order.save()
                sell_user = Users.objects.get(user_id=sell_order.user)
                sell_user.available_funds += transaction_fund
                sell_user.save()
                ### decrease holdings
                selling_list = Holdings.objects.filter(user=sell_order.user, stock=sell_order.stock).all()
                discount_amount = transaction_volume
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
                
                buy_order.executed_volume += transaction_volume
                buy_user = Users.objects.get(user_id=buy_order.user)
                buy_user.available_funds -= transaction_fund
                buy_user.blocked_funds -= buy_bid_price * transaction_volume
                buy_user.save()

                self.ohlcv_transaction(market, buy_order.stock, transaction_price, transaction_volume)
                Holdings.objects.create(user=buy_order.user, stock=buy_order.stock, volume=transaction_volume, bid_price=transaction_price, bought_on=day)

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
                transaction_volume = available_volume
            else:
                transaction_volume = remain_volume

            # Transaction
            transaction_fund = transaction_price * transaction_volume
                
            buy_order.executed_volume += transaction_volume
            buy_user = Users.objects.get(user_id=buy_order.user)
            buy_user.available_funds -= transaction_fund
            buy_user.blocked_funds -= buy_bid_price * transaction_volume
            buy_user.save()
            
            self.ohlcv_transaction(market, buy_order.stock, transaction_price, transaction_volume)
            
            stock.unallocated -= transaction_volume  
            stock.price = buy_bid_price  
            stock.save()
            Holdings.objects.create(user=buy_order.user, stock=buy_order.stock, volume=transaction_volume, bid_price=transaction_price, bought_on=day)

            if transaction_volume == remain_volume:
                buy_order.status = "COMPLETED"
                
            buy_order.save()
        return Response({"message":"Orders Executed Successfully!"})

    def ohlcv_transaction(market, stock, transaction_price, transaction_volume):            
        ### increase ohlcv
        ohlcvs = Ohlcv.objects.filter(day=market.day, stock=stock.id)
        if ohlcvs.exists():
            ohlcv = ohlcvs.first()
            ohlcv.high = max(ohlcv.high, transaction_price)
            ohlcv.low = min(ohlcv.high, transaction_price)
            ohlcv.volume += int(transaction_volume)
            ohlcv.save()
        else:
            previous = Ohlcv.objects.filter(day=market.day-1, stock=stock.id)
            if previous.exists():
                open_price = previous.first().close
            else:
                open_price = stock.price
            Ohlcv.objects.create(
                day = market.day,
                stock = stock,
                open = open_price,
                high = max(open_price, transaction_price),
                low = min(open_price, transaction_price),
                close = transaction_price,
                volume = transaction_volume,
                market = market
            )                


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
        try:
            market = Market_day.objects.get(day=day)
        except:
            return Response(status=status.HTTP_404_NOT_FOUND)
        stock_list = Stocks.objects.all()
        returnData = []
        for stock in stock_list:
            ohlcv = Ohlcv.objects.filter(market=market, stock=stock)
            if ohlcv.exists():
                ohlcv = ohlcv.first()
            else:
                previous = Ohlcv.objects.filter(day=day-1, stock=stock)
                if previous.exists():
                    open_price = previous.first().close
                else:
                    open_price = stock.price
                ohlcv = Ohlcv.objects.create(
                    day=market.day,
                    stock=stock,
                    open=open_price,
                    high=open_price,
                    low=open_price,
                    close=open_price,
                    volume=0,
                    market=market
                )

            serializer = OhlcvSerializer(ohlcv)
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
            if market.latest('day').status == "OPEN":
                return Response(status=status.HTTP_204_NO_CONTENT)
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
            market = Market_day.objects.get(day=day)
        
        stock_list = Stocks.objects.all()
        for stock in stock_list:
            previous = Ohlcv.objects.filter(day=day-1, stock=stock)
            if previous.exists():
                open_price = previous.first().close
            else:
                open_price = stock.price

            Ohlcv.objects.create(
                day=market.day,
                stock=stock,
                open=open_price,
                high=open_price,
                low=open_price,
                close=open_price,
                volume=0,
                market=market
            )
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
            ohlcvs = Ohlcv.objects.filter(day=market.day,stock=stock.id)
            if ohlcvs.exists():
                ohlcv = ohlcvs.first()
                ohlcv.close = stock.price
                ohlcv.save()
            else:
                previous = Ohlcv.objects.filter(day=market.day-1, stock=stock)
                if previous.exists():
                    open_price = previous.first().close
                else:
                    open_price = stock.price
                Ohlcv.objects.create(
                    day=market.day,
                    stock=stock,
                    open=open_price,
                    high=open_price,
                    low=open_price,
                    close=open_price,
                    volume=0,
                    market=market
                )

        return Response(status=status.HTTP_204_NO_CONTENT)


class WalletView(APIView):
    permission_classes = [
        IsAuthenticated,
    ]
    authentication_classes = [
        TokenAuthentication,
    ]
    def get(self, request, format=None):
        user_id = request.user.id
        user = Users.objects.get(user_id=user_id)
        user.available_funds = 0
        user.save()
        
        return Response({"Withdraw money successfully!"}, status=status.HTTP_200_OK)

    def post(self, request, format=None):
        user_id = request.user.id
        user = Users.objects.get(user_id=user_id)
        data = request.data
        serializer = WalletSerializer(data=data)        
        if serializer.is_valid(raise_exception=True):
            user.available_funds += data['amount']
            user.save()
            return Response({"Added money to wallet!"}, status=status.HTTP_200_OK)
            

class WatchListView(APIView):
    permission_classes = [
        IsAuthenticated,
    ]
    authentication_classes = [
        TokenAuthentication,
    ]

    def get(self, request, format=None):
        watchlists = Watchlist.objects.all()
        returnData = []
        for watchlist in watchlists:
            stocks = Watchlist_Stock.objects.filter(watchlist=watchlist.id).all()
            serializer = Watchlist_StockSerializer(stocks, many=True)
            eachData = {
                'id': watchlist.id,
                'name': watchlist.name,
                'stocks': []
            }
            for each in stocks:
                serializer = StockSerializer(each.stock)
                eachData['stocks'].append(serializer.data)
            returnData.append(eachData)
        
        return Response(returnData)

    def post(self, request, format=None):
        data = request.data
        
        serializer = WatchlistSerializer(data=data)
        if serializer.is_valid(raise_exception=True):
            obj = serializer.save()
        
        if 'stocks' not in data.keys() or data['stocks'] == '':
            return Response({"stocks":["This field is required."]}, status=status.HTTP_400_BAD_REQUEST)
        elif type(data['stocks']) != list:
            return Response({"stocks":["A valid list of integer is required."]}, status=status.HTTP_400_BAD_REQUEST)
        else:
            stocks = []
            for each in data['stocks']:
                if type(each) != int:  
                    Response({"stocks2":["A valid list of integer is required."]}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    serializer_data = {
                        'watchlist': obj.id,
                        'stock': each
                    }
                    serializer = Watchlist_StockSerializer(data=serializer_data)
                    if serializer.is_valid(raise_exception=True):
                        serializer.save()
                        stocks.append(each)
        
            response_data = {
                'id': obj.id,
                'name': obj.name,
                'stocks': stocks
            }
            return Response(response_data, status=status.HTTP_201_CREATED)
            

# class WatchDetailView(APIView):
#     permission_classes = [
#         IsAuthenticated,
#     ]
#     authentication_classes = [
#         TokenAuthentication,
#     ]

#     def get(self, request, pk, format=None):
#         try:
#             watchlist = Watchlist.objects.get(pk=pk)
#         except Watchlist.DoesNotExist:
#             raise Http404
#         stocks = Watchlist_Stock.objects.filter(watchlist=watchlist.id).all()
#         serializer = Watchlist_StockSerializer(stocks, many=True)
#         returnData = {
#             'id': watchlist.id,
#             'stocks': []
#         }
#         for each in serializer.data:
#             returnData['stocks'].append(each['stock'])
        
#         return Response(returnData)
            

class WatchDeleteView(APIView):
    permission_classes = [
        IsAuthenticated,
    ]
    authentication_classes = [
        TokenAuthentication,
    ]

    def delete(self, request, pk, fk, format=None):
        try:
            watchlist = Watchlist.objects.get(pk=pk)
        except Watchlist.DoesNotExist:
            raise Http404
        stock = Watchlist_Stock.objects.get(watchlist=watchlist.id, stock=fk)
        stock.delete()
        
        return Response(status=status.HTTP_204_NO_CONTENT)

    def patch(self, request, pk, fk, format=None):
        try:
            watchlist = Watchlist.objects.get(pk=pk)
        except Watchlist.DoesNotExist:
            raise Http404
        stock = Watchlist_Stock.objects.filter(watchlist=watchlist.id, stock=fk)
        if not stock.exists():
            serializer_data = {
                'watchlist': pk,
                'stock': fk
            }
            serializer = Watchlist_StockSerializer(data=serializer_data)
            if serializer.is_valid(raise_exception=True):
                serializer.save()

        stocks = Watchlist_Stock.objects.filter(watchlist=watchlist.id).all()
        serializer = Watchlist_StockSerializer(stocks, many=True)
        returnData = {
            'id': watchlist.id,
            'stocks': []
        }
        for each in serializer.data:
            returnData['stocks'].append(each['stock'])
        
        return Response(returnData)


class GainerView(APIView):
    def get(self,request,*args,**kwargs):
        markets = Market_day.objects
        if markets.exists():
            market = markets.filter().latest('day')
        else:
            market = Market_day.objects.create(day=1, status="OPEN")
        gainer = Ohlcv.objects.filter(day=market.day).annotate(gain=(F('close') - F('open')) * (100 / F('open'))).order_by('-gain')
        returnData = []
        for gain in gainer:
            serializer = StockSerializer(gain.stock)
            data = serializer.data
            data['gain'] = '{:.2f}'.format(gain.gain)
            returnData.append(data)

        return Response(returnData)


class LoserView(APIView):
    def get(self,request,*args,**kwargs):
        markets = Market_day.objects
        if markets.exists():
            market = markets.filter().latest('day')
        else:
            market = Market_day.objects.create(day=1, status="OPEN")
        loser = Ohlcv.objects.filter(day=market.day).annotate(lose=(F('close') - F('open')) * (100 / F('open'))).order_by('lose')
        returnData = []
        for lose in loser:
            serializer = StockSerializer(lose.stock)
            data = serializer.data
            data['lose'] = '{:.2f}'.format(lose.lose)
            returnData.append(data)

        return Response(returnData)