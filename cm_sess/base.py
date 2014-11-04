# -*- coding: utf-8 -*-

import abc

class SessBase:
  """ リモート接続セッションのベースクラス
  """
  __metaclass__ = abc.ABCMeta
  
  def write_log(self, logger, level, msg):
    """ APIを判別できるようにクラス名をつけてmsgをログ出力
    """ 
    getattr(logger, level)("%s: %s" % (self.__class__.__name__, msg))

  @abc.abstractmethod
  def open(self):
    return

  @abc.abstractmethod
  def get_snmp_acl(self, **kw):
    return

  @abc.abstractmethod
  def update_snmp_acl(self, acl_diff_dict, **kw):
    return

  @abc.abstractmethod
  def save_exit_config(self, **kw):
    return

  @abc.abstractmethod
  def close(self, **kw):
    return
