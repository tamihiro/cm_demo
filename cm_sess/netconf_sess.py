# -*- coding: utf-8 -*-

import re
import logging
import os
from os.path import dirname, join
from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from ipaddr import IPv4Network

from cm_sess.netconf_yaml.preflist import *

from base import SessBase

# set形式のjinja2テンプレート
template_path = join(dirname(__file__), './netconf_templates/preflist_tmpl.set')

class NetconfSess(SessBase):
  """netconfセッション用クラス
  """
  def __init__(self, server, user_login, pass_login, logger_name, netconf_port=830, rpc_timeout=20):
    self.server = server
    self.user_login = user_login
    self.pass_login = pass_login
    self.logger = logging.getLogger(logger_name)
    self.netconf_port = netconf_port
    self.rpc_timeout = rpc_timeout
    self.closed = True
    self.acl_name = 'SNMP-ACCESS'
    self.last_acl = list()

  def open(self):
    """サーバに接続
    """
    self.dev = Device(
            host=self.server.ipaddr, 
            user=self.user_login, 
            password=self.pass_login, 
            gather_facts=False, 
            )
    # デフォルト30秒を更新
    self.dev.open(gather_facts=False)
    if self.dev.connected:
      setattr(self.dev, 'timeout', self.rpc_timeout)
      self.cu = Config(self.dev)
      self.closed = False
      self.write_log(self.logger, 'info', "%s (%s): 接続しました." % (self.server.ipaddr, self.server.model, ))
    else:
      raise RuntimeError("%s: %s: 接続できませんでした." % (self.__class__.__name__, self.server.ipaddr))

  def get_snmp_acl(self, **kw):
    """ SNMPアクセスリストを取得
    >>> for pl in PrefListTable(self.dev).get():
    ...   if pl.name == 'SNMP-ACCESS':
    ...     pp.pprint(json.loads(pl.entries.to_json()))
    ...
    {   u'10.0.0.1/32': {   u'prefix': u'10.0.0.1/32'},
        u'172.25.8.0/24': {   u'prefix': u'172.25.8.0/24'},
        u'172.31.30.0/24': {   u'prefix': u'172.31.30.0/24'},
        u'192.168.11.0/24': {   u'prefix': u'192.168.11.0/24'}}

    """
    set_last_acl = kw.get('set_last_acl', True)
    acl = list()
    for pl in PrefListTable(self.dev).get():
      if pl.name == self.acl_name:
        # prefix-list name がマッチしたらエントリを取得
        acl = map(IPv4Network, pl.entries.keys())
        break
    # 取得できなかった場合はカラのリストを返す
    if set_last_acl: self.last_acl = acl
    return acl

  def update_snmp_acl(self, acl_diff_dict, **kw):
    """ SNMPアクセスリストを更新
    """
    if not os.access(template_path, os.R_OK):
      self.close()
      raise IOError("テンプレートファイルを開けません.: %s" % (template_path, ))

    if kw.get('prompt', False):
      # 確認プロンプトを表示
      reply = raw_input("変更しますか? ")
      if not re.match('\s*(y|yes|)\s*$', reply.rstrip(), re.I):
        self.write_log(self.logger, 'info', "%s: 更新をキャンセルします." % (self.server.ipaddr, ))
        self.close()
        return False

    new_acl = list(set(self.last_acl) - set(acl_diff_dict['del'])) + acl_diff_dict['add']
    template_vars = dict([
            ('acl_dict', dict([
                     (self.acl_name, [ n.with_prefixlen for n in new_acl ]), 
                     ])), 
            ])
    # 新しいACLを機器にロードする
    self.cu.load(template_path=template_path, template_vars=template_vars)
    return self.get_snmp_acl(set_last_acl=False)

  def save_exit_config(self, **kw):
    """ コミット or ロールバック
    """
    if kw.get('prompt', False):
      # 確認プロンプトを表示
      if not re.match('\s*(y|yes|)\s*$', raw_input("保存しますか? ").rstrip(), re.I): 
        self.write_log(self.logger, 'info', "%s: ロールバックします." % (self.server.ipaddr, ))        
        self.cu.rollback()
        current_acl = self.get_snmp_acl(set_last_acl=False)
        failed = set(current_acl) != set(self.last_acl)
        self.close()
        if failed:
          self.write_log(self.logger, 'error', "%s: 正常にロールバックできませんでした.: %s%s" % (
                  self.server.ipaddr, 
                  self.last_acl, 
                  current_acl
                  ))
          raise RuntimeError('failed!')
        return
    # コミット
    self.cu.commit()
    self.write_log(self.logger, 'debug', "%s: コミットしました." % (self.server.ipaddr, ))    

  def close(self):
    """ セッション終了
    """
    if self.closed: return
    self.dev.close()
    self.write_log(self.logger, 'debug', "%s: セッションを閉じました." % (self.server.ipaddr, ))
    self.closed = True

