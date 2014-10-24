# -*- coding: utf-8 -*-

from os.path import splitext

from cm_sess.eapi_sess import EapiHttpSess
from cm_sess.netconf_sess import NetconfSess
from cm_sess.telnet_sess import TelnetSess

class Agent:
  """設定変更対象エージェント
  """
  def __init__(self, ipaddr):
    self.ipaddr = ipaddr
    self.model = self.__class__.__name__.lower()

class Arista(Agent):
  def get_sess(self, pass_login, pass_enable, logger_name):
    return EapiHttpSess(self, 'admin', pass_login, logger_name, )

class Brocade(Agent):
  def get_sess(self, pass_login, pass_enable, logger_name):
    return TelnetSess(self, pass_login, pass_enable, logger_name, 
                      screen_dump=splitext(__file__)[0]+"_telnet_dump", )

class Cisco(Agent):
  def get_sess(self, pass_login, pass_enable, logger_name):
    return TelnetSess(self, pass_login, pass_enable, logger_name, 
                      screen_dump=splitext(__file__)[0]+"_telnet_dump", )

class Juniper(Agent):
  def get_sess(self, pass_login, pass_enable, logger_name):
    #return TelnetSess(self, pass_login, None, logger_name, user_login='admin', 
    #                  screen_dump=splitext(__file__)[0]+"_telnet_dump", )
    return NetconfSess(self, 'admin', pass_login, logger_name, )

