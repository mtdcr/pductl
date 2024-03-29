#!/usr/bin/env python3
#
# pductl - Control outlets of ATEN PE PDUs (SNMP v2/v3)
#
# Copyright (c) 2022 Andreas Oberritter
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
#
# Example configuration [~/.pductl]:
#
# {
#   "format": 1,
#   "pdus": {
#     "pdu1": {
#       "node": "pdu1",              (default)
#       "service": "snmp",           (default)
#       "username": "administrator", (default for SNMPv3)
#       "authkey": "AAAAAAAAAAAAAA", (required for SNMPv3)
#       "privkey": "BBBBBBBBBBBBBB"  (required for SNMPv3)
#     },
#     "pdu2": {
#       "authkey": "CCCCCCCCCCCCCC",
#       "privkey": "DDDDDDDDDDDDDD"
#     },
#     "pdu3": {
#       "node": "192.168.21.19",
#       "service": "16161",
#       "username": "joe",
#       "authkey": "EEEEEEEEEEEEEE",
#       "privkey": "FFFFFFFFFFFFFF"
#     },
#     "pdu4": {
#       "community": "private"       (default for SNMPv2)
#     },
#     "pdu5": {
#     }
#   }
# }
#
#
# Usage:
#
# pductl [-p <PDU>] list
# pductl [-p <PDU>] <on|off|reboot|status> <OUTLET> [<OUTLET> ...]
#

import asyncio
import json
import pathlib
from argparse import ArgumentParser, RawTextHelpFormatter
from sys import stderr

from . import AtenPE


class PduCtrl(AtenPE):
    def __init__(self, name, params):
        node = params.get("node", name)
        serv = params.get("service", "snmp")
        community = params.get("community", "private")
        username = params.get("username", "administrator")
        authkey = params.get("authkey")
        privkey = params.get("privkey")
        super().__init__(
            node=node,
            serv=serv,
            community=community,
            username=username,
            authkey=authkey,
            privkey=privkey,
        )

    async def switchOutlets(self, outlets, state):
        await self._set(dict([("outlet%dStatus" % outlet.id, state) for outlet in outlets]), 0)

    async def queryOutlets(self, outlets):
        varbind_table = await self._get([("outlet%dStatus" % outlet.id, 0) for outlet in outlets])
        for outlet, var_binds in zip(outlets, varbind_table):
            yield (outlet, str(var_binds[1]))


def fatal(msg):
    print("Error: %s" % msg, file=stderr)
    exit(1)


def state_path():
    return pathlib.Path.home() / ".pductl"


def load_state():
    try:
        with open(state_path(), "r") as f:
            state = json.load(f)
            fmt = state.get("format")
            if fmt is not None and int(fmt) == 1:
                return state
    except FileNotFoundError:
        pass
    except Exception as e:
        fatal("%s: %s" % (state_path(), e))
    return {}


# Load connection parameters and and cached outlet names from file
state = load_state()
pdus = state.get("pdus", {})
if not pdus:
    fatal("No PDUs found! Please create or modify '%s'." % state_path())


# Build command-line parser and help texts
ap = ArgumentParser()

pdu_names = sorted([*pdus.keys()])
ap.add_argument("-p", "--pdu", choices=pdu_names, default=pdu_names[0])

sp = ap.add_subparsers(help="commands", dest="cmd")

outlet_cmds = {
    "status": "Get current state of outlet(s)",
    "off": "Turn off outlet(s)",
    "on": "Turn on outlet(s)",
    "reboot": "Reboot outlet(s)",
}

outlets_help = ""
for k, v in pdus.items():
    outlets_help += "Outlets for %s: {" % k + ",".join(v.get("outlets", [])) + "}\n"

for cmd, cmd_help in outlet_cmds.items():
    p = sp.add_parser(cmd, formatter_class=RawTextHelpFormatter, help=cmd_help)
    p.add_argument("outlet", nargs="+", help=outlets_help, metavar="OUTLET")

simple_cmds = {
    "list": "List known outlets",
    "info": "Show information about the device",
}

for cmd, help in simple_cmds.items():
    sp.add_parser(cmd, help=help)


async def main(args):
    # Create the PDU controller object for the selected PDU
    ctrl = PduCtrl(args.pdu, pdus.get(args.pdu))
    ctrl.initialize()

    if args.cmd == "list":
        async for outlet in ctrl.outlets():
            print("%s: %s" % (outlet.id, outlet.name))

    elif args.cmd == "info":
        print("Name: %s" % await ctrl.deviceName())
        print("Model: %s" % await ctrl.modelName())
        print("Firmware: %s" % await ctrl.deviceFWversion())
        print("MAC: %s" % await ctrl.deviceMAC())

    elif args.cmd in outlet_cmds.keys():
        outlets = [outlet async for outlet in ctrl.outlets()]

        if args.outlet and "ALL" not in args.outlet:
            diff = set(args.outlet).difference(
                set([outlet.name if outlet.name else str(outlet.id) for outlet in outlets])
            )
            if diff:
                fatal("Invalid argument(s): %s" % diff)
            outlets = [outlet for outlet in outlets if outlet.name in args.outlet or str(outlet.id) in args.outlet]

        if args.cmd == "status":
            async for outlet, state in ctrl.queryOutlets(outlets):
                line = "[%02d]" % outlet.id
                if outlet.name:
                    line += " " + outlet.name
                line += ": " + state
                if state == "on":
                    line += ", consuming " + await ctrl.outletPower(outlet.id) + " W"
                print(line)
        else:
            await ctrl.switchOutlets(outlets, args.cmd)


def run():
    asyncio.run(main(ap.parse_args()))


if __name__ == "__main__":
    run()
