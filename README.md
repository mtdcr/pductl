# pductl - Control outlets of ATEN PE PDUs

## Installation

```sh
pip install atenpdu
```
 
## Example configuration [~/.pductl]
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
    },
    "pdu4": {
      "community": "private"
    },
    "pdu5": {
    }
  }
}
```

* `authkey` and `privkey` are required for SNMPv3. On absence, SNMPv2c gets used.
* `community` defaults to `private` for SNMPv2c.
* `node` defaults to PDU entry's name.
* `service` defaults to `snmp`, i.e. port 161.
* `username` defaults to `administrator` for SNMPv3.

## Usage

```sh
pductl [-p <PDU>] list
pductl [-p <PDU>] <on|off|reboot|status> <OUTLET> [<OUTLET> ...]
```

Use `ALL` to select all outlets.
