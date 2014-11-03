# -*- coding: utf-8 -*-

import re
import logging
import os
from time import sleep
from os.path import dirname, join
from ncclient import manager
from ncclient.xml_ import *
from ncclient.operations.rpc import RPC
from ipaddr import IPv4Address, IPv4Network

from base import SessBase

# Brocade固有のリソース名
brocade_acl_urn = 'urn:brocade.com:mgmt:brocade-ip-access-list'
brocade_mgmt_urn = 'urn:brocade.com:mgmt:brocade-ras'

# <get-config>でACLを取得するためのXPATHフィルタ
brocade_acl_xpath_tmpl = "/ip-acl/ip/access-list/standard[name='{acl_name}']"

# ACL追加(or削除)するためのXMLテンプレート
brocade_acl_std_xml_tmpl = """
  <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <ip-acl xmlns="%(urn)s">
      <ip>
        <access-list>
          <standard>
            <name>{acl_name}</name>
            <hide-ip-acl-std>
              <seq>
                <seq-id>{seq_id}</seq-id>
                <action>permit</action>
                <src-host-any-sip>{src_host}</src-host-any-sip>
                <src-mask>{network_mask}</src-mask>
              </seq>
            </hide-ip-acl-std>
          </standard>
        </access-list>
      </ip>
    </ip-acl>
  </config>
""" % {'urn': brocade_acl_urn, }

""" 
<copy-config>が未サポートなので、startupを更新するためにBrocade独自のRPCを発行する必要がある

  <rpc>
    <bna-config-cmd xmlns="urn:brocade.com:mgmt:brocade-ras">
      <src>running-config</src>
      <dest>startup-config</dest>
    </bna-config-cmd>
  </rpc>
  <rpc-reply>
    <session-id>3</session-id>
    <status>in-progress</status>
  </rpc-reply>
  <rpc>
    <bna-config-cmd-status xmlns="urn:brocade.com:mgmt:brocade-ras">
      <session-id>_id_</session-id>
      </bna-config-cmd-status>
    </bna-config-cmd-status>
  </rpc>
  <rpc-reply>
    <status>completed</status>
    <status-string></status-string>
  </rpc-reply>
"""

# new_ele()を実行するとタグの先頭についてくるネームスペースをつけないようにする
new_ele_no_ns = lambda tag, attrs={}, **extra: etree.Element(qualify(tag, None), attrs, **extra)

# startup更新リクエスト
class VdxSaveConfig(RPC):
  def request(self):
    node = new_ele_no_ns("bna-config-cmd", {'xmlns': brocade_mgmt_urn, }, )
    src = etree.Element('src')
    src.text = 'running-config'
    node.append(src)
    dest = etree.Element('dest')
    dest.text = 'startup-config'
    node.append(dest)
    return self._request(node)

# startup更新結果取得リクエスト
class VdxGetSaveStatus(RPC):
  def request(self, sess_id):
    node = new_ele_no_ns("bna-config-cmd-status", {'xmlns': brocade_mgmt_urn, }, )
    session_id = etree.Element('session-id')
    session_id.text = sess_id
    node.append(session_id)
    return self._request(node)

# ncclient.manager内で宣言されているVENDOR_OPERATIONSに追加しておく
manager.VENDOR_OPERATIONS['vdx_save_config'] = VdxSaveConfig
manager.VENDOR_OPERATIONS['vdx_get_save_status'] = VdxGetSaveStatus

get_save_status_retry = 5

class NetconfVdxSess(SessBase):
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
    self.acl_name = 'MANAGEMENT-ACCESS'
    # 辞書の値にseq-idを保持する
    self.last_acl_d = dict()

  def check_rsp_error(self, rsp, error_msg):
    """ RPCReply.okをチェック
    """ 
    if not rsp.ok:
      self.close(error_msg=error_msg)
      raise RuntimeError("%s: %s: %s" % (self.__class__.__name__, self.server.ipaddr, rsp.xml))
    return

  def open(self):
    """サーバに接続
    """
    self.dev = manager.connect(
            host=self.server.ipaddr, 
            username=self.user_login, 
            password=self.pass_login, 
            hostkey_verify=False,
            )
    if self.dev.connected:
      setattr(self.dev, 'timeout', self.rpc_timeout)
      self.closed = False
      self.write_log(self.logger, 'info', "%s (%s): 接続しました." % (self.server.ipaddr, self.server.model, ))
    else:
      raise RuntimeError("%s: %s: 接続できませんでした." % (self.__class__.__name__, self.server.ipaddr))

  def get_snmp_acl(self, **kw):
    """ SNMPアクセスリストを取得(VDXでは管理インターフェイスのACLにしてます)
    """
    set_last_acl = kw.get('set_last_acl', True)
    acl_d = dict()

    def get_acl(eles):
      for ele in eles.getchildren():
        if ele.tag == qualify('action', brocade_acl_urn): action = ele.text
        if ele.tag == qualify('seq-id', brocade_acl_urn): seq_id = int(ele.text)
        if ele.tag == qualify('src-host-any-sip', brocade_acl_urn): src_host_any_sip = ele.text
        if ele.tag == qualify('src-host-ip', brocade_acl_urn): src_host_ip = ele.text
        if ele.tag == qualify('src-mask', brocade_acl_urn): src_mask = ele.text if ele.text != '0.0.0.0' else None
      if action != 'permit': 
        raise RuntimeError("unable to handle %s action" % action)
      if src_host_ip != '0.0.0.0': 
        raise RuntimeError("unable to handle src-host-ip %s" % src_host_ip)
      acl_d[IPv4Network(src_host_any_sip + (src_mask and '/' + src_mask or ''))] = seq_id

    for eles in self.dev.get_config(
          source='running', 
          filter=('xpath', brocade_acl_xpath_tmpl.format(acl_name=self.acl_name, )), 
          ).data.iterdescendants():
      if eles.tag == qualify('seq', brocade_acl_urn):
        try:
          get_acl(eles)
        except (NameError, RuntimeError), e:
          self.write_log(self.logger, 
                         'warn', 
                         "%s: ACLエントリを判別できません.: %s: %s" % (
                               self.server.ipaddr, 
                               [(ele.tag, ele.text) for ele in eles.getchildren()], 
                               e.message, ), )

    if set_last_acl: self.last_acl_d = acl_d
    return acl_d.keys()

  def update_snmp_acl(self, acl_diff_dict, **kw):
    """ SNMPアクセスリストを更新
    NOTE
    Every NETCONF <edit-config> request should have a one-to-one mapping with a Brocade command. 
    You cannot combine two CLI operations into one NETCONF request.
    """
    if kw.get('prompt', False):
      # 確認プロンプトを表示
      reply = raw_input("変更しますか? ")
      if not re.match('\s*(y|yes|)\s*$', reply.rstrip(), re.I):
        self.write_log(self.logger, 'info', "%s: 更新をキャンセルします." % (self.server.ipaddr, ))
        self.close()
        return False

    # rollbackと同等の処理をする場合
    if kw.get('rollback'): 
      # self.last_acl_dをrunningから取得
      self.get_snmp_acl()
      # edit-configで削除したACLを追加する
      acl2add_d = acl_diff_dict['del']
      # edit-configで追加したACLを削除する
      acl2del_d = acl_diff_dict['add']

    else:
      acl2add_d = acl_diff_dict['add']
      acl2del_d = acl_diff_dict['del']

    def get_seq_id(seq_ids):
      """順不動前提のACLに追加するエントリのseq-id
      """
      seq_ids_dec = map(lambda n: n / 10, seq_ids)
      seq_ids_dec.sort()
      for i in range(len(seq_ids_dec) - 1):
        if seq_ids_dec[i] + 1 < seq_ids_dec[i + 1]:
          return (seq_ids_dec[i] + 1) * 10
      return (seq_ids_dec[-1] + 1) * 10

    # rpc-reply受信時に更新するseq-idのリスト
    seq_id_update = self.last_acl_d.values() 

    # 削除
    my_ipaddr = IPv4Address(self.dev._session.transport.sock.getsockname()[0])
    for to_del in acl2del_d:
      if my_ipaddr in to_del:
        # マネージメントへの接続不可になる可能性があるので中断
        self.close(error_msg="%sを削除するとNETCONFセッションを継続できなくなる可能性があります." % (str(to_del), ))
        raise RuntimeError("%s: %s: %s in %s!" % (self.__class__.__name__, self.server.ipaddr, str(my_ipaddr), str(to_del), ))

      xml = brocade_acl_std_xml_tmpl.format(
                  urn = brocade_acl_urn,
                  acl_name = self.acl_name, 
                  seq_id = self.last_acl_d[to_del],
                  src_host = str(to_del.network),
                  network_mask = str(to_del.hostmask),)
      # operation="delete"を追加
      ele_conf = etree.fromstring(xml)
      ele_conf.find('.//%s' % qualify('seq', brocade_acl_urn)).set('operation', 'delete')
      xml = etree.tostring(ele_conf)

      # ACLエントリ削除RPCを発行
      rsp = self.dev.edit_config(target='running', config=xml)
      self.check_rsp_error(rsp, "%sから%sを削除できませんでした." % (self.acl_name, str(to_del), ))
      seq_id_update.remove(self.last_acl_d[to_del])

    # 追加
    for to_add in acl2add_d:
      new_seq_id = get_seq_id(seq_id_update)
      xml = brocade_acl_std_xml_tmpl.format(
                  urn = brocade_acl_urn,
                  acl_name = self.acl_name, 
                  seq_id = new_seq_id,
                  src_host = str(to_add.network),
                  network_mask = str(to_add.hostmask),)

      # ACLエントリ追加RPCを発行
      rsp = self.dev.edit_config(target='running', config=xml)
      self.check_rsp_error(rsp, "%sに%sを追加できませんでした." % (self.acl_name, str(to_del), ))
      seq_id_update.append(new_seq_id)

    # 更新後のACLをrunningから取得
    return self.get_snmp_acl(set_last_acl=False)

  def save_exit_config(self, **kw):
    """コミット or ロールバック
    """
    if kw.get('prompt', False) and not re.match('\s*(y|yes|)\s*$', raw_input("保存しますか? ").rstrip(), re.I): 
      # candidateが未サポートなので元のACLに戻す
      self.write_log(self.logger, 'info', "%s: 元のACLに戻します." % (self.server.ipaddr, ))        
      self.update_snmp_acl(kw.get('acl_diff_dict'), rollback=True)

    # candidateが未サポートなのでBrocade独自のRPCでstartupの更新処理
    rsp = self.dev.vdx_save_config()
    self.check_rsp_error(rsp, "startup更新リクエストでエラーが発生しました.")

    et = etree.fromstring(rsp.xml)
    rsp_status = et.find('./%s' % qualify('status', brocade_mgmt_urn)).text
    rsp_sess_id = et.find('./%s' % qualify('session-id', brocade_mgmt_urn)).text
    if rsp_status not in ('in-progress', 'completed', ):
      self.close(error_msg="startup更新リクエストのステータスを取得できませんでした.")
      raise RuntimeError("%s: %s: %s" % (self.__class__.__name__, self.server.ipaddr, rsp.xml))

    # 更新処理のステータスをチェック
    for i in range(get_save_status_retry):
      if rsp_status == 'completed': break
      # completedを受信するまでの所要時間10秒前後(観測)
      sleep(3)
      rsp = self.dev.vdx_get_save_status(rsp_sess_id)
      self.check_rsp_error(rsp, "startup更新ステータス取得リクエストでエラーが発生しました.")
      et = etree.fromstring(rsp.xml)
      rsp_status = et.find('./%s' % qualify('status', brocade_mgmt_urn)).text

    if rsp_status != 'completed': 
      self.close(error_msg="startup更新処理の完了を確認できませんでした.")
      raise RuntimeError("%s: %s: %s" % (self.__class__.__name__, self.server.ipaddr, rsp.xml))

    self.write_log(self.logger, 'debug', "%s: startupを更新しました." % (self.server.ipaddr, ))
    return

  def close(self, error_msg=None):
    """ セッション終了
    """
    if self.closed: return
    self.dev.close_session()
    if error_msg:
      self.write_log(self.logger, 'error', "%s: %s" % (self.server.ipaddr, error_msg))
    else:
      self.write_log(self.logger, 'debug', "%s: セッションを閉じました." % (self.server.ipaddr, ))
    self.closed = True

