import json

import pytest

from remarkapy.api import Client




def test_list_documents_smoke(tmp_path):
    api = Client()
    collection = api.get_item_ids()
    docs = [doc.to_dict() for doc in collection]

    file_path = tmp_path / "output.json"
    file_path.write_text(json.dumps(docs, indent=4), encoding="utf-8")

    assert file_path.exists()
