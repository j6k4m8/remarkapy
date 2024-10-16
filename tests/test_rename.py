import sys
sys.path.insert(0, '../')
from remarkapy.api import Client
import json

api = Client()

data = api.rename_item('ITEM_ID', new_name='coolname')
