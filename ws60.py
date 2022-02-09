import json, time, configparser, logging
from threading import Thread
from websocket import create_connection, WebSocketConnectionClosedException
from datetime import datetime
from operator import itemgetter
import json, hmac, hashlib, time, requests, base64, logging, configparser
from requests.auth import AuthBase
from time import sleep

class CoinbaseExchangeAuth(AuthBase):
    def __init__(self, api_key, secret_key, passphrase):
        self.api_key = api_key
        self.secret_key = secret_key
        self.passphrase = passphrase

    def __call__(self, request):
        timestamp = str(int(time.time()))
        message = timestamp + request.method + request.path_url + (request.body or '')
        hmac_key = base64.b64decode(self.secret_key)
        signature = hmac.new(hmac_key, message.encode(), hashlib.sha256)
        signature_b64 = base64.b64encode(signature.digest())

        request.headers.update({
            'CB-ACCESS-SIGN': signature_b64,
            'CB-ACCESS-TIMESTAMP': timestamp,
            'CB-ACCESS-KEY': self.api_key,
            'CB-ACCESS-PASSPHRASE': self.passphrase,
            'Content-Type': 'application/json'
        })
        return request

def main():
  url_limit = 'https://api.pro.coinbase.com/orders'
  url_accounts = 'https://api.pro.coinbase.com/accounts/'

  auth = CoinbaseExchangeAuth("2646bacd8b7b48f3d6b18ea6fb584c6a",
                            "TLHIWveCJik9+HpNN1cO9NmO5DdcvhFvHefcmbYFOtN0p24xNjWFETgPts9/WqCFlFnSB6OUs9lCMHFTB28g+A==",
                            "Adamlarinadami12!")

  body_buy = {
    'type': 'limit',
    'side': 'buy',
    #'price': '1',
    #'size': '0.01',
    'funds': '1',
    'product_id': 'ETH-EUR',
  }

  body_sell = {
    'type': 'limit',
    'side': 'sell',
    'stop': 'loss',
    'price': '1',
    'size': '0.01',
    'stop_price': '1',
    #'funds': '1',
    'product_id': 'ETH-EUR',
  }

  ws = None
  thread = None
  thread_running = False
  thread_keepalive = None
  body = {
    'ETH-EUR': { 'id': '999696ed-7b80-4817-a2b9-c1763b56b0a7', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'BTC-EUR': { 'id': 'a8e792fc-118b-4f57-9f94-c8744be45b72', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'DOGE-EUR': { 'id': '4cdd2238-a67c-4032-bb88-9dd45fbe9180', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'SHIB-EUR': { 'id': '7f144bce-be20-4787-801f-903e5eb73986', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'ADA-EUR': { 'id': '974026a8-55ab-412d-96d6-8a7c58390258', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'DOT-EUR': { 'id': '957f9ed6-a787-42f1-9c74-b72ad687b1af', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'AVAX-EUR': { 'id': 'fb331f67-4ddc-41cf-aa4d-62d8ff0451c3', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'XTZ-EUR': { 'id': '5f447e52-a342-44cd-93cd-b9f5e264b680', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'SOL-EUR': { 'id': '15b8f315-a039-476d-9a09-7af773e32894', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'ICP-EUR': { 'id': '544ea39a-ec42-4d06-9e8c-9c44e6705bcc', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'LTC-EUR': { 'id': '003e9a85-29b0-4e5d-99ec-2aac8d6b3650', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'BCH-EUR': { 'id': '596df804-50e2-43a1-bdab-a2218ca8e2e8', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'EOS-EUR': { 'id': '9690f17f-4925-404d-a34b-ae770e7fc102', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'XLM-EUR': { 'id': 'cc4b47b1-fa8e-4a79-880e-7e1addcea285', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'ATOM-EUR': { 'id': 'e90693c9-b57a-4010-b92e-781796cb630e', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'AXS-EUR': { 'id': '64d97b8c-b4c0-475d-b0fa-27d3bff283f2', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'ETC-EUR': { 'id': 'a169be54-2ed4-45b6-88b7-f02d6144788a', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'OMG-EUR': { 'id': 'adeb8c4f-312b-43f1-bbe7-c42cd2c2cd9e', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'LINK-EUR': { 'id': '3653b693-d034-4596-8202-adaef8a443e3', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'BAT-EUR': { 'id': 'e5e7cee7-1a14-4a63-9f10-0a6e028d558f', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'CHZ-EUR': { 'id': '55bf81d1-d4c6-4332-84b5-f91a7a9d776b', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'CRO-EUR': { 'id': '8cb60ae0-6549-49e7-96b0-5854a0dd69d7', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'ZRX-EUR': { 'id': '1c84d27b-a31d-4f44-a1ff-b78f07b1d790', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'ALGO-EUR': { 'id': '690c5c6a-0f9f-4822-a654-66c427c8943f', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    '1INCH-EUR': { 'id': '821fcde8-61d5-4ed2-8083-54ceac10dee6', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'MANA-EUR': { 'id': '69ef48cc-11d4-4998-8ea9-79b2f0767a99', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'PERP-EUR': { 'id': 'af665ba8-fda8-48b3-90e6-4d9bc508df4d', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'MIR-EUR': { 'id': '42c31227-777b-4ccb-83e2-269cc91cbec0', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'BAND-EUR': { 'id': 'f625ae51-b208-429d-bc8f-aea2dc5bcd03', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'NMR-EUR': { 'id': 'b4080aa7-50a9-446e-87ca-dfbfced5d276', 'price': '0', 'price_last': '0' , 'raise_count': '0'},
    'IOTX-EUR': { 'id': 'cb6d2a6c-cdc0-4eed-8e05-a8e50c73e11a', 'price': '0', 'price_last': '0' , 'raise_count': '0'},
    'CGLD-EUR': { 'id': '5488a1f3-a4d4-45c7-b1f6-6692e6eb3862', 'price': '0', 'price_last': '0' , 'raise_count': '0'},
    'UMA-EUR': { 'id': 'f163cbc5-83f5-458a-bb26-82c1ef16e67d', 'price': '0', 'price_last': '0' , 'raise_count': '0'},
    'FORTH-EUR': { 'id': '1513b8df-ff2c-43ef-9674-33f7e66bd172', 'price': '0', 'price_last': '0' , 'raise_count': '0'},
    'UNI-EUR': { 'id': 'e8e4c6fe-2956-4ad7-bc6e-1093d5286feb', 'price': '0', 'price_last': '0' , 'raise_count': '0'},
    'RAD-EUR': { 'id': 'e842c4ba-c365-4eac-aafa-7a4ff5c9b5f2', 'price': '0', 'price_last': '0' , 'raise_count': '0'},
    'NU-EUR': { 'id': '18935352-b7dc-4eb1-9ac9-3c2791452680', 'price': '0', 'price_last': '0' , 'raise_count': '0'},
    'FIL-EUR': { 'id': 'c1e699eb-9293-46e1-9b67-15d1ac3b09c6', 'price': '0', 'price_last': '0' , 'raise_count': '0'},
    'AAVE-EUR': { 'id': '56414903-6019-4394-ab0c-4de3fe9131ce', 'price': '0', 'price_last': '0' , 'raise_count': '0'},
    'TRAC-EUR': { 'id': 'b4ef362a-0b6f-4183-aed4-681bfa1ab92d', 'price': '0', 'price_last': '0' , 'raise_count': '0'},
    'BADGER-EUR': { 'id': 'f6ecdf7d-13b8-4f6c-853b-533ab6f7f3f1', 'price': '0', 'price_last': '0' , 'raise_count': '0'},
    'GRT-EUR': { 'id': '20a3e408-5c41-43db-832c-3967882b5a11', 'price': '0', 'price_last': '0' , 'raise_count': '0'},
    'BNT-EUR': { 'id': '0e0bda62-35c0-4812-9042-07946b8c8303', 'price': '0', 'price_last': '0' , 'raise_count': '0'},
    'AUCTION-EUR': { 'id': '13ec7a09-79cd-4063-b4f1-6a6465326933', 'price': '0', 'price_last': '0' , 'raise_count': '0'},
    'RLY-EUR': { 'id': '74063daf-ef64-4879-bca9-b59c577d8624', 'price': '0', 'price_last': '0' , 'raise_count': '0'},
    'NKN-EUR': { 'id': '5eaf40b7-6c99-4501-9b88-0029b2a10e9d', 'price': '0', 'price_last': '0' , 'raise_count': '0'},
    'SNX-EUR': { 'id': 'cf47725c-97f2-4110-8070-2070f1c293a9', 'price': '0', 'price_last': '0' , 'raise_count': '0'},
    'SUSHI-EUR': { 'id': '6caaaaae-8830-4435-a9a1-95dc36a1bdb6', 'price': '0', 'price_last': '0' , 'raise_count': '0'},
    'MATIC-EUR': { 'id': '62af9f10-8894-48b5-bbb4-dd84cd4ad690', 'price': '0', 'price_last': '0' , 'raise_count': '0'},
    'SKL-EUR': { 'id': 'f7c992bb-5a13-41db-924e-bf12043873b0', 'price': '0', 'price_last': '0' , 'raise_count': '0'},
    'DDX-EUR': { 'id': 'd410b852-2f1b-4451-be11-087f47329edf', 'price': '0', 'price_last': '0' , 'raise_count': '0'},
    'MASK-EUR': { 'id': '58ba49be-48eb-4cda-a4f3-39f4e3fec682', 'price': '0', 'price_last': '0' , 'raise_count': '0'},
    'ANKR-EUR': { 'id': '7db97b7c-d286-4aa8-a6fc-1d1dc1f5e68c', 'price': '0', 'price_last': '0' , 'raise_count': '0'},
    'XYO-EUR': { 'id': '2d6639b9-7fbb-4e4e-b17c-3ef936d9a126', 'price': '0', 'price_last': '0' , 'raise_count': '0'},
    'CRV-EUR': { 'id': 'd490f24d-7e3e-499b-8d2e-084beb0c4a39', 'price': '0', 'price_last': '0' , 'raise_count': '0'},
    'REQ-EUR': { 'id': '453ac73a-0d1b-4eee-94e1-aa0add4c891c', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'ARPA-EUR': { 'id': '6fe79262-80be-460e-9414-b0c20b277abf', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'LCX-EUR': { 'id': 'facc160a-2956-4c5a-83da-2d56c1e3e825', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'SUKU-EUR': { 'id': '77e1a658-8edf-44aa-bee0-e45b3028decf', 'price': '0', 'price_last': '0', 'raise_count': '0' },
    'KRL-EUR': { 'id': '31979859-2cbf-43dd-951c-a7b159f31d4d', 'price': '0', 'price_last': '0', 'raise_count': '0' }
  }

  logging.basicConfig(filename='ws60.csv', format= '%(message)s', level=logging.INFO)

  def websocket_thread():
    global ws

    ws = create_connection("wss://ws-feed.pro.coinbase.com")
    ws.send(
      json.dumps(
        {
          "type": "subscribe",
          "product_ids": ['BTC-EUR', 'ETH-EUR', 'DOGE-EUR', 'SHIB-EUR',
            'ADA-EUR', 'DOT-EUR', 'XTZ-EUR', 'AVAX-EUR', 'SOL-EUR',
            'ICP-EUR', 'LTC-EUR', 'BCH-EUR', 'EOS-EUR', 'XLM-EUR',
            'ATOM-EUR', 'AXS-EUR', 'ETC-EUR', 'OMG-EUR', 'LINK-EUR',
            'BAT-EUR', 'CHZ-EUR', 'CRO-EUR', 'ZRX-EUR', 'ALGO-EUR',
            '1INCH-EUR', "MANA-EUR", "PERP-EUR", "MIR-EUR",
            "BAND-EUR", "NMR-EUR", "IOTX-EUR", "CGLD-EUR",
            "UMA-EUR", "FORTH-EUR", "UNI-EUR", "NU-EUR",
            "BAND-EUR", "FIL-EUR", "AAVE-EUR", "TRAC-EUR",
            "BADGER-EUR", "GRT-EUR", "BNT-EUR", "AUCTION-EUR",
            "RLY-EUR", "NKN-EUR", "SNX-EUR", "SUSHI-EUR",
            "MATIC-EUR", "SKL-EUR", "DDX-EUR", "MASK-EUR",
            "ANKR-EUR", "XYO-EUR", "CRV-EUR", "REQ-EUR",
            "ARPA-EUR", "LCX-EUR", "SUKU-EUR", "KRL-EUR"
          ],
          "channels": ["matches"],
        }
      )
    )

    thread_keepalive.start()
    while not thread_running:
      try:
        data = ws.recv()
        if data != "":
          msg = json.loads(data)
          product_id = msg['product_id']
          price = float(msg['price'])
          body[product_id]['price'] = price

        else:
          msg = {}
      except ValueError as e:
        print(e)
        print("{} - data: {}".format(e, data))
      except Exception as e:
        print(e)
        print("{} - data: {}".format(e, data))
    # else:
    #   if "result" not in msg:
    #     print(msg)

    try:
      if ws:
        ws.close()
    except WebSocketConnectionClosedException:
      pass
    finally:
      thread_keepalive.join()

  interval = 60
  limit = 0.1
  raise_count_limit = 5
  funds = 10
  profit = 2.5
  loss = 1.0
  config = configparser.ConfigParser()
  config.read('ws.ini')
  if 'parameters' in config:
    interval = int(config['parameters']['interval'])
    limit = float(config['parameters']['limit'])
    raise_count_limit = float(config['parameters']['raise count limit'])
    funds = int(config['parameters']['funds'])
    profit = float(config['parameters']['profit'])
    loss = float(config['parameters']['loss'])
  else:
    config = configparser.ConfigParser()
    config['parameters'] = { 'interval': interval,
                             'limit': limit,
                             'raise count limit': raise_count_limit,
                             'funds': funds,
                             'profit': profit,
                             'loss': loss }
    with open('ws.ini', 'w' ) as configfile:
      config.write(configfile)

  def websocket_keepalive(interval=interval):
    global ws

    #is_bought = False
    while ws.connected:
      ws.ping("keepalive")

      list = []
      #logging.info(datetime.now().strftime('%d/%m/%Y %H:%M:%S'))
      for product_id in body:
        price_last = float(body[product_id]['price_last'])
        price = float(body[product_id]['price'])
        if price <= 0:
          break
        body[product_id]['price_last'] = price
        if price_last <= 0:
          price_last = price
        price_diff = price - price_last
        percent = round((price_diff / price) * 100, 2)

        raise_count = body[product_id]['raise_count']
        if (percent < limit and percent >= 0) or (percent <= 0 and percent > -1 * limit):
          raise_count = 0
        elif percent >= limit:
          raise_count = int(raise_count) + 1
        body[product_id]['raise_count'] = raise_count

        #try:
        #  response = requests.request("GET", str(url_accounts)+body[product_id]['id'], auth=auth, timeout=1)
        #  logging.info(response.json())
        #except requests.exceptions.Timeout as e:
        #  logging.info(e)

        if raise_count >= raise_count_limit:
          was_request_successful = False
          while was_request_successful == False:
            try:
              #body_limit['type'] = "market"
              #body_limit['side'] = "buy"
              body_buy['product_id'] = product_id
              #body_limit['price'] = price
              body_buy['funds'] = funds
              response = requests.post(url_limit, data=json.dumps(body_buy), auth=auth, timeout=1)
              logging.info("buy order: " + response.text)
              was_request_successful = True
            except requests.exceptions.Timeout as e:
              logging.info(e)

          size = "0"
          was_request_successful = False
          while was_request_successful == False:
            try:
              response = requests.get(str(url_accounts)+body[product_id]['id'], auth=auth, timeout=1)
              data = json.loads(response.text)
              size = data['available']
              was_request_successful = True
            except requests.exceptions.Timeout as e:
              logging.info(e)

          was_request_successful = False
          while was_request_successful == False:
            try:
              response = requests.get(url_products+product_id, auth=auth, timeout=1)
              data = json.loads(response.text)
              inc = float(data['quote_increment'])
              #logging.info("inc: " + str(inc))
              was_request_successful = True
            except requests.exceptions.Timeout as e:
              logging.info(e)

          was_request_successful = False
          while was_request_successful == False:
            try:
              #del body_limit['funds']
              #body_limit['type'] = "stop"
              #body_limit['side'] = "sell"
              body_sell['price'] = (price + profit*price/100) - ((price + profit*price/100) % inc)
              body_sell['stop_price'] = (price - loss*price/100) - ((price - loss*price/100) % inc)
              #logging.info("price: " + str(body_sell['price']))
              #logging.info("stop price: " + str(body_sell['stop_price']))
              body_sell['size'] = size
              body_sell['product_id'] = product_id
              response = requests.post(url_limit, data=json.dumps(body_sell), auth=auth, timeout=1)
              #logging.info("sell order: " + response.text)
              was_request_successful = True
            except requests.exceptions.Timeout as e:
              logging.info(e)

        #  try:
        #    response = requests("GET", url_limit, auth=auth, timeout=1)
        #    data = json.loads(response.text)
        #    if len(data) == 0:
        #      is_bought = False
        #  except requests.exceptions.Timeout as e:
        #    logging.info(e)

        #  if is_bought == False:
        #   try:
        #     body_limit['type'] = "market"
        #     body_limit['side'] = "buy"
        #     body_limit['price'] = str(price)
        #     body_limit['funds'] = str(100)
        #     response = requests.post(url_limit, data=json.dumps(body_limit), auth=auth, timeout=1)
        #     logging.info("buy order: " + response.text)
        #   except requests.exceptions.Timeout as e:
        #     logging.info(e)

        #    size = "0"
        #    try:
        #      response = requests.request("GET", str(url_accounts)+body[product_id]['id'], auth=au$
        #      data = json.loads(response.text)
        #      size = data[0]['available']
        #    except requests.exceptions.Timeout as e:
        #      logging.info(e)

        #    try:
        #      body_limit['type'] = "stop"
        #      body_limit['side'] = "sell"
        #      body_limit['price'] = str(price + 5*price/100)
        #      body_limit['stop_price'] = str(price - 3*price/100)
        #      body_limit['size'] = float(size)
        #      response = requests.post(url_limit, data=json.dumps(body), auth$
        #      logging.info("stop order: " + response.text)
        #    except requests.exceptions.Timeout as e:
        #      logging.info(e)

        #    is_bought = True

        list.append((product_id, percent, price))

      list = sorted(list, key=itemgetter(1), reverse=True)

      for e in list:
        logging.info(str(e[0]) + ","
                     + datetime.now().strftime('%d/%m/%Y %H:%M:%S') + ","
                     + str(e[1]) + ","
                     + datetime.now().strftime('%d/%m/%Y %H:%M:%S') + ","
                     + str(e[2]))

      time.sleep(interval)

  thread = Thread(target=websocket_thread)
  thread_keepalive = Thread(target=websocket_keepalive)
  thread.start()

if __name__ == "__main__":
  try:
    main()
  except Exception as e:
    logging.info("main crashed. Error: %s", e)
