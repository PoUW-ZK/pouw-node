import pytest
import requests


# Turns into a normal pass once the node serves its API, then remove the marker
@pytest.mark.xfail(reason="pouw-node#59: the node does not serve its REST API yet",
                   raises=requests.ConnectionError)
def test_health(service):
    r = requests.get(service("node-1", 8000) + "/health", timeout=10)
    assert r.status_code == 200
