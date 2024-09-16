from remarkapy.configfile import get_config_or_raise

def test_sanity():
    assert 1 == 1

def test_can_find_config():
    config = get_config_or_raise()
    assert config.usertoken
    assert config.devicetoken
