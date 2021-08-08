# TP-Link Archer C2300 API client

An example implementation of the auth. mechanism and e2e encrypted comms. via the LuCI HTTP API on official TP-Link firmware.

### Compatible (tested) versions
* **Firmware:** 1.1.1 Build 20200918 rel.67850(4555)
* **Hardware:** Archer C2300 v2.0

### Example usage
```
from . import tplink

api = tplink.TPLinkClient('192.168.1.1')
api.connect('password in plaintext')

print(api.get_client_list())
```

### Example auth responses

* On wrong password

`{'errorcode': 'login failed', 'success': False, 'data': {'failureCount': 1, 'errorcode': '-5002', 'attemptsAllowed': 9}}`

* On exceeded max auth attempts (usually 10)

`{'errorcode': 'exceeded max attempts', 'success': False, 'data': {'failureCount': 10, 'attemptsAllowed': 0}}`

* If some other user is logged in

`{'errorcode': 'user conflict', 'success': False, 'data': {}}`

* On successful auth

`{'success': True, 'data': {'stok': '94640fd8887fb5750d6a426345581b87'}}`

### Todo
* Implement logout action

___

Licensed under GNU GPL v3
