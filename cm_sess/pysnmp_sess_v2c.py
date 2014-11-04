# -*- coding: utf-8 -*-

""" pysnmpを使ったSNMPエージェント機能
"""

from pysnmp.entity.rfc3413.oneliner import cmdgen
import re

class PysnmpSessV2cError(Exception):
  def __init__(self, value):
    self.value = value
  def __str__(self):
    return self.value

class PysnmpSessV2c(object):
  def __init__(self, 
      port=161, 
      timeout=1, 
      retries=3, 
      community='sakura-open'):
    self.port = port
    self.retries = retries
    self.timeout = timeout
    self.community = community
    self.my_cmdgen = cmdgen.CommandGenerator()

  def sync_get(self, agent, *oids):
    error_indication, error_status, error_index, varbinds = self.my_cmdgen.getCmd( 
        cmdgen.CommunityData(self.community), 
        cmdgen.UdpTransportTarget((agent, self.port), timeout=self.timeout, retries=self.retries), 
        *oids 
        )
    if error_indication:
      raise PysnmpSessV2cError("%s: %s: %s" % (self.__class__.__name__, agent, error_indication))
    else:
      if error_status:
        raise PysnmpSessV2cError("%s: %s: %s at %s" % 
            self.__class__.__name__,
            agent, 
            error_status.prettyPrint(), 
            error_index and varbinds[int(error_index)-1][0] or '?' 
            )
      else:
        d = dict()
        for name, val in varbinds:
          d[name] = val
        return d

  def sync_getnext(self, agent, *oids):
    error_indication, error_status, error_index, varbind_table = self.my_cmdgen.nextCmd( 
        cmdgen.CommunityData(self.community), 
        cmdgen.UdpTransportTarget((agent, self.port), timeout=self.timeout, retries=self.retries), 
        *oids 
        )
    if error_indication:
      raise PysnmpSessV2cError("%s: %s: %s" % (self.__class__.__name__, agent, error_indication))
    else:
      if error_status:
        raise PysnmpSessV2cError("%s: %s: %s at %s" % 
            self.__class__.__name__, 
            agent, 
            error_status.prettyPrint(), 
            error_index and varbind_table[-1][int(error_index)-1][0] or '?' 
            )
      else:
        d = dict()
        for varbind_tablerow in varbind_table:
          for name, val in varbind_tablerow:
            d[name] = val
        return d
              
  def sync_bulkget(self, agent, nonrepeaters, maxrepetitions, maxrows, *oids):
    error_indication, error_status, error_index, varbind_table = self.my_cmdgen.bulkCmd( 
        cmdgen.CommunityData(self.community), 
        cmdgen.UdpTransportTarget((agent, self.port), timeout=self.timeout, retries=self.retries), 
        nonrepeaters, 
        maxrepetitions, 
        *oids, 
        maxRows=maxrows
        )
    if error_indication:
      raise PysnmpSessV2cError("%s: %s: %s" % (self.__class__.__name__, agent, error_indication))
    else:
      if error_status:
        raise PysnmpSessV2cError("%s: %s: %s at %s" % 
            self.__class__.__name__, 
            agent, 
            error_status.prettyPrint(), 
            error_index and varbind_table[-1][int(error_index)-1][0] or '?' 
            )
      else:
        d = dict()
        for varbind_tablerow in varbind_table:
          for name, val in varbind_tablerow:
            d[name] = val
        return d
              
def snmpget_sysdescr(router):
  sess = PysnmpSessV2c()
  oid = '1.3.6.1.2.1.1.1.0'
  res = sess.sync_get(router, oid)
  return str(res.values()[0])

def snmpget_counters(router, *oids):
  sess = PysnmpSessV2c()
  sess.retries = 1
  d = sess.sync_get(router, *oids)
  return dict(zip(map(str, d.keys()), map(int, d.values())))

if __name__ == '__main__':
  pass

