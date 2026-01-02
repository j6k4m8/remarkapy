from remarkapy.api import Client


def test_replace_hash_and_size_updates_size():
    client = Client.__new__(Client)
    file_list = "\n".join(
        [
            "header",
            "oldhash:1:doc.metadata:1:123",
            "otherhash:1:doc.content:1:999",
        ]
    )

    result = client._replace_hash_and_size(
        file_list, search_for=".metadata", new_hash="newhash", new_size=456
    )

    lines = result.splitlines()
    assert lines[1].split(":")[0] == "newhash"
    assert lines[1].split(":")[4] == "456"
    assert lines[2] == "otherhash:1:doc.content:1:999"


def test_replace_hash_and_size_keeps_size_when_none():
    client = Client.__new__(Client)
    file_list = "\n".join(
        [
            "header",
            "oldhash:1:doc.metadata:1:123",
        ]
    )

    result = client._replace_hash_and_size(
        file_list, search_for=".metadata", new_hash="newhash"
    )

    line = result.splitlines()[1]
    assert line.split(":")[0] == "newhash"
    assert line.split(":")[4] == "123"
