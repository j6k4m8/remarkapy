import sys
sys.path.insert(0, '../')
from remarkapy.api import Client
import json

api = Client()


# Specify the file path
file_path = 'output.json'

# Fetch a collection of metadata items
collection = api.get_items()

# Convert the first document in the collection to a dictionary
docs = []
for doc in collection:
    docs.append(doc.to_dict())

# Dump the dictionary to a JSON file
with open(file_path, 'w') as json_file:
    json.dump(docs, json_file, indent=4)

print(f"Data has been saved to {file_path}.")
#