from service.app import handler


def test_handler():
    assert handler({})["ok"]
