#
# Copyright (c) 2019 Andreas Oberritter
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
from collections import namedtuple

from pysnmp.hlapi.asyncio import *
from pysnmp.smi import builder, compiler
from pysnmp.smi.error import MibNotFoundError


class AtenPEError(Exception):
    pass


class AtenPE(object):
    _MIB_MODULE = 'ATEN-PE-CFG'
    _MIB_SRCURI = 'http://mibs.thola.io/asn1/'

    def __init__(self, node, serv='snmp', community='private', username='administrator', authkey=None, privkey=None):
        self._addr = (node, serv)
        self._snmp_engine = SnmpEngine()
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
        self._snmp_args = []

    def initialize(self):
        try:
            transport_target = UdpTransportTarget(self._addr)
        except PySnmpError as exc:
            raise AtenPEError(str(exc))

        self._snmp_args = [
            self._snmp_engine,
            self._auth_data,
            transport_target,
            ContextData()
        ]

        mibBuilder = builder.MibBuilder()
        compiler.addMibCompiler(mibBuilder, sources=[self._MIB_SRCURI])
        try:
            mibBuilder.loadModules(self._MIB_MODULE)
        except MibNotFoundError as exc:
            raise AtenPEError(str(exc))

    async def _set(self, objects_values, *args):
        if not self._snmp_args:
            raise AtenPEError('Method initialize() needs to be called first')

        err_indication, err_status, _, _ = await setCmd(
            *self._snmp_args,
            *[ObjectType(ObjectIdentity(self._MIB_MODULE, obj, *args), value) for obj, value in objects_values.items()]
        )
        if err_indication:
            raise AtenPEError(err_indication)
        if err_status:
            raise AtenPEError(err_status.prettyPrint())

    async def _get(self, objects):
        if not self._snmp_args:
            raise AtenPEError('Method initialize() needs to be called first')

        err_indication, err_status, _, varbind_table = await getCmd(
            *self._snmp_args,
            *[ObjectType(ObjectIdentity(self._MIB_MODULE, *obj)) for obj in objects]
        )
        if err_indication:
            raise AtenPEError(err_indication)
        if err_status:
            raise AtenPEError(err_status.prettyPrint())
        return varbind_table

    async def _nrOutlets(self):
        return int(await self._getAttribute('outletnumber'))

    async def _outletIDs(self):
        return range(1, await self._nrOutlets() + 1)

    async def outlets(self):
        Outlet = namedtuple('outlet', ['id', 'name'])

        varbind_table = await self._get([('outletName', n) for n in await self._outletIDs()])
        for n, var_binds in enumerate(varbind_table):
            name = var_binds[1]
            if not (name and name[0]):
                name = ''
            yield Outlet(n + 1, str(name))

    async def _getAttribute(self, name, index=0):
        varbind_table = await self._get([(name, index)])
        return varbind_table[-1][1]

    def _resolve(self, s):
        return str(s.getNamedValues().getName(s))

    async def deviceMAC(self):
        return str(await self._getAttribute('deviceMAC'))

    async def outletPower(self, outlet):
        return str(await self._getAttribute('outletPower', outlet))

    async def displayOutletStatus(self, outlet):
        return self._resolve(await self._getAttribute('displayOutletStatus', outlet))

    async def setOutletStatus(self, outlet, state):
        await self._set({ 'outlet%dStatus' % outlet: state }, 0)

    async def modelName(self):
        return str(await self._getAttribute('modelName'))

    async def deviceFWversion(self):
        return str(await self._getAttribute('deviceFWversion'))

    async def deviceName(self):
        return str(await self._getAttribute('deviceName'))
