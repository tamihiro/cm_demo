# -*- coding: utf-8 -*-

from os.path import splitext
import re

from cm_sess.eapi_sess import EapiHttpSess
from cm_sess.netconf_juniper_sess import NetconfJuniperSess
from cm_sess.netconf_vdx_sess import NetconfVdxSess
from cm_sess.telnet_sess import TelnetSess

class Agent:
  """設定変更対象エージェント
  """
  def __init__(self, ipaddr):
    self.ipaddr = ipaddr
    self.model = re.sub('([a-z0-9])([A-Z])', 
                        r'\1_\2', 
                        re.sub('(.)([A-Z][a-z0-9]+)', 
                               r'\1_\2', 
                               self.__class__.__name__, ), 
                       ).lower()

class Arista(Agent):
  def get_sess(self, pass_login, pass_enable, logger_name, **kw):
    return EapiHttpSess(self, 'admin', pass_login, logger_name, )

class BrocadeNetiron(Agent):
  def get_sess(self, pass_login, pass_enable, logger_name, **kw):
    screen_dump  = kw.get('dump_telnet', False)  and splitext(__file__)[0]+"_telnet_dump" or None
    return TelnetSess(self, pass_login, pass_enable, logger_name, 
                      screen_dump=screen_dump, )

class BrocadeVdx(Agent):
  def get_sess(self, pass_login, pass_enable, logger_name, **kw):
    return NetconfVdxSess(self, 'admin', pass_login, logger_name, )

class Cisco(Agent):
  def get_sess(self, pass_login, pass_enable, logger_name, **kw):
    screen_dump  = kw.get('dump_telnet', False)  and splitext(__file__)[0]+"_telnet_dump" or None
    return TelnetSess(self, pass_login, pass_enable, logger_name, 
                      screen_dump=screen_dump, )

class Juniper(Agent):
  def get_sess(self, pass_login, pass_enable, logger_name, **kw):
    #screen_dump  = kw.get('dump_telnet', False)  and splitext(__file__)[0]+"_telnet_dump" or None
    #return TelnetSess(self, pass_login, None, logger_name, user_login='admin', 
    #                  screen_dump=screen_dump, )
    return NetconfJuniperSess(self, 'admin', pass_login, logger_name, )

