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

import asyncio
import typing as t
from collections import namedtuple
from pathlib import Path

import async_timeout
from pysnmp.error import PySnmpError
from pysnmp.hlapi.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    usmAesCfb128Protocol,
    usmHMACMD5AuthProtocol,
)
from pysnmp.hlapi.asyncio.cmdgen import getCmd, setCmd
from pysnmp.smi import builder


class AtenPEError(Exception):
    pass


class AtenPE(object):
    _MIB_MODULE = "ATEN-PE-CFG"

    def __init__(
        self,
        node: t.Union[bytes, str],
        serv: t.Union[bytes, str, int] = "snmp",
        community: str = "private",
        username: str = "administrator",
        authkey: t.Optional[str] = None,
        privkey: t.Optional[str] = None,
    ) -> None:
        self._addr = (node, serv)
        self._snmp_engine = SnmpEngine()
        self._lock = asyncio.Lock()
        if authkey and privkey:
            self._auth_data = UsmUserData(
                username,
                authkey,
                privkey,
                authProtocol=usmHMACMD5AuthProtocol,
                privProtocol=usmAesCfb128Protocol,
            )
        else:
            self._auth_data = CommunityData(community)
        self._snmp_args: t.List[t.Any] = []
        self._snmp_engine.getMibBuilder().addMibSources(builder.DirMibSource(Path(__file__).parent / "mibs"))

    def close(self) -> None:
        self._snmp_engine.transportDispatcher.closeDispatcher()

    def initialize(self) -> None:
        try:
            transport_target = UdpTransportTarget(self._addr)
        except PySnmpError as exc:
            raise AtenPEError(*exc.args) from exc

        self._snmp_args = [
            self._snmp_engine,
            self._auth_data,
            transport_target,
            ContextData(),
        ]

    async def _set(self, objects_values, *args):
        if not self._snmp_args:
            raise AtenPEError("Method initialize() needs to be called first")

        async with self._lock:
            for _ in range(3):
                try:
                    async with async_timeout.timeout(3):
                        set_result = await setCmd(
                            *self._snmp_args,
                            *[
                                ObjectType(ObjectIdentity(self._MIB_MODULE, obj, *args), value)
                                for obj, value in objects_values.items()
                            ],
                        )
                        err_indication, err_status, _, _ = await set_result
                except asyncio.exceptions.TimeoutError:
                    pass
                else:
                    break
            else:
                raise AtenPEError("Timeout")

        if err_indication:
            raise AtenPEError(err_indication)
        if err_status:
            raise AtenPEError(err_status.prettyPrint())

    async def _get(self, objects: t.Any) -> t.Any:
        if not self._snmp_args:
            raise AtenPEError("Method initialize() needs to be called first")

        async with self._lock:
            for _ in range(3):
                try:
                    async with async_timeout.timeout(3):
                        get_result = await getCmd(
                            *self._snmp_args, *[ObjectType(ObjectIdentity(self._MIB_MODULE, *obj)) for obj in objects]
                        )
                        err_indication, err_status, _, varbind_table = get_result
                except asyncio.exceptions.TimeoutError:
                    pass
                else:
                    break
            else:
                raise AtenPEError("Timeout")

        if err_indication:
            raise AtenPEError(err_indication)
        if err_status:
            raise AtenPEError(err_status.prettyPrint())
        return varbind_table

    async def _nrOutlets(self) -> int:
        return int(await self.getAttribute("outletnumber"))

    async def _outletIDs(self) -> range:
        return range(1, await self._nrOutlets() + 1)

    async def outlets(self) -> t.AsyncGenerator:
        Outlet = namedtuple("Outlet", ["id", "name"])

        varbind_table = await self._get([("outletName", n) for n in await self._outletIDs()])
        for n, var_binds in enumerate(varbind_table):
            name = var_binds[1]
            if not (name and name[0]):
                name = ""
            yield Outlet(n + 1, str(name))

    async def getAttribute(self, name: str, index: int = 0) -> t.Any:
        varbind_table = await self._get([(name, index)])
        return varbind_table[-1][1]

    def _resolve(self, s: t.Any) -> str:
        return str(s.getNamedValues().getName(s))

    async def deviceMAC(self) -> str:
        return str(await self.getAttribute("deviceMAC"))

    async def outletPower(self, outlet: int) -> str:
        return str(await self.getAttribute("outletPower", outlet))

    async def displayOutletStatus(self, outlet: int) -> str:
        return self._resolve(await self.getAttribute("displayOutletStatus", outlet))

    async def setOutletStatus(self, outlet: int, state: str) -> None:
        await self._set({"outlet%dStatus" % outlet: state}, 0)

    async def modelName(self) -> str:
        return str(await self.getAttribute("modelName"))

    async def deviceFWversion(self) -> str:
        return str(await self.getAttribute("deviceFWversion"))

    async def deviceName(self) -> str:
        return str(await self.getAttribute("deviceName"))
