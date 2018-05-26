#
# Copyright (c) 2018 Andreas Oberritter
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

from collections import namedtuple
from functools import lru_cache


class AtenPE(object):
    _MIB_MODULE = 'ATEN-PE-CFG'
    _MIB_SRCURI = 'http://mibs.snmplabs.com/asn1/'

    def __init__(self, node, serv='snmp', community='private', username='administrator', authkey=None, privkey=None):
        self._prepareSnmpArgs(node, serv, community, username, authkey, privkey)
        self._prepareMibs()

    def _prepareSnmpArgs(self, node, serv, community, username, authkey, privkey):
        from pysnmp.hlapi import (
            CommunityData, ContextData, SnmpEngine, UdpTransportTarget,
            UsmUserData, usmAesCfb128Protocol, usmHMACMD5AuthProtocol)

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

    def _prepareMibs(self):
        from pysnmp.smi import builder, compiler
        mibBuilder = builder.MibBuilder()
        compiler.addMibCompiler(mibBuilder, sources=[self._MIB_SRCURI + '@mib@'])
        mibBuilder.loadModules(self._MIB_MODULE)

    def _set(self, objects_values, *args):
        from pysnmp.hlapi import (
            setCmd, ObjectIdentity, ObjectType)
        next(setCmd(
            *self._snmp_args,
            *[ObjectType(ObjectIdentity(self._MIB_MODULE, obj, *args), value) for obj, value in objects_values.items()]
        ))

    def _get(self, objects, *args):
        from pysnmp.hlapi import (
            getCmd, ObjectIdentity, ObjectType)
        return getCmd(
            *self._snmp_args,
            *[ObjectType(ObjectIdentity(self._MIB_MODULE, obj, *args)) for obj in objects]
        )

    def _next(self, objects, *args):
        from pysnmp.hlapi import (
            nextCmd, ObjectIdentity, ObjectType)
        return nextCmd(
            *self._snmp_args,
            *[ObjectType(ObjectIdentity(self._MIB_MODULE, obj, *args)) for obj in objects]
        )

    def _iterate(self, g):
        errorIndication, errorStatus, errorIndex, varBinds = next(g)
        if errorIndication:
            print(errorIndication)
        elif errorStatus:
            print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        else:
            return [binds[1] for binds in varBinds]

        return []

    @property
    @lru_cache(maxsize=1)
    def _nrOutlets(self):
        return self._getAttribute('outletnumber')

    @property
    def _outletIDs(self):
        return range(1, self._nrOutlets + 1)

    @property
    def outlets(self):
        Outlet = namedtuple('outlet', ['id', 'name'])
        g = self._next(['outletName'])
        for n in self._outletIDs:
            name, = self._iterate(g)
            if not (name and name[0]):
                name = ''
            yield Outlet(n, str(name))

    def _getIndexedAttribute(self, name, index):
        s, = self._iterate(self._get([name], index))
        return s

    def _getAttribute(self, name):
        s, = self._iterate(self._next([name]))
        return s

    def _resolve(self, s):
        return str(s.getNamedValues().getName(s))

    @property
    @lru_cache(maxsize=1)
    def deviceMAC(self):
        return str(self._getAttribute('deviceMAC'))

    def outletPower(self, outlet):
        return str(self._getIndexedAttribute('outletPower', outlet))

    def outletPowerDissipation(self, outlet):
        return str(self._getIndexedAttribute('outletPowerDissipation', outlet))

    def displayOutletStatus(self, outlet):
        return self._resolve(self._getIndexedAttribute('displayOutletStatus', outlet))

    def setOutletStatus(self, outlet, state):
        self._set({ 'outlet%dStatus' % outlet: state }, 0)
