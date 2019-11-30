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


class AtenPE(object):
    _MIB_MODULE = 'ATEN-PE-CFG'
    _MIB_SRCURI = 'http://mibs.snmplabs.com/asn1/'

    def __init__(self, node, serv='snmp', community='private', username='administrator', authkey=None, privkey=None):
        self._prepareSnmpArgs(node, serv, community, username, authkey, privkey)

    def _prepareSnmpArgs(self, node, serv, community, username, authkey, privkey):
        if authkey and privkey:
            self._snmp_args = [
                SnmpEngine(),
                UsmUserData(
                    username,
                    authkey,
                    privkey,
                    authProtocol=usmHMACMD5AuthProtocol,
                    privProtocol=usmAesCfb128Protocol,
                ),
                UdpTransportTarget((
                    node,
                    serv,
                )),
                ContextData()
            ]
        else:
             self._snmp_args = [
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((
                    node,
                    serv,
                )),
                ContextData()
            ]

    def loadMibs(self):
        mibBuilder = builder.MibBuilder()
        compiler.addMibCompiler(mibBuilder, sources=[self._MIB_SRCURI + '@mib@'])
        mibBuilder.loadModules(self._MIB_MODULE)

    async def _set(self, objects_values, *args):
        await setCmd(
            *self._snmp_args,
            *[ObjectType(ObjectIdentity(self._MIB_MODULE, obj, *args), value) for obj, value in objects_values.items()]
        )

    async def _get(self, objects):
        _, _, _, varbind_table = await getCmd(
            *self._snmp_args,
            *[ObjectType(ObjectIdentity(self._MIB_MODULE, *obj)) for obj in objects]
        )
        return varbind_table

    async def _nrOutlets(self):
        return await self._getAttribute('outletnumber')

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
        return varbind_table[0][1]

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
