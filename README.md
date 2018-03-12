# pductl - Control outlets of ATEN PE PDUs

## Requirements:

* Python 3
* PySNMP

## Installation:

Copy `ATEN-PE-CFG.py` into `~/.pysnmp/mibs/`.
 
## Example configuration [~/.pductl]:
```json
{
  "format": 1,
  "pdus": {
    "pdu1": {
      "node": "pdu1",
      "service": "snmp",
      "username": "administrator",
      "authkey": "AAAAAAAAAAAAAA",
      "privkey": "BBBBBBBBBBBBBB"
    },
    "pdu2": {
      "authkey": "CCCCCCCCCCCCCC",
      "privkey": "DDDDDDDDDDDDDD"
    },
    "pdu3": {
      "node": "192.168.21.19",
      "service": "16161",
      "username": "joe",
      "authkey": "EEEEEEEEEEEEEE",
      "privkey": "FFFFFFFFFFFFFF"
    }
  }
}
```

* `authkey` and `privkey` are required.
* `node` defaults to PDU entry's name.
* `service` defaults to `"snmp"`.
* `username` defaults to `"administrator"`.

## Usage:
```sh
pductl update
pductl [-p <PDU>] list
pductl [-p <PDU>] <on|off|reboot|status> <OUTLET> [<OUTLET> ...]
```
