# -*- coding: utf-8 -*-

import re
import logging
import urllib, urllib2
from contextlib import closing
import json
import traceback
from ipaddr import IPv4Network

from base import SessBase

class EapiHttpSess(SessBase):
  """eapiセッション用クラス
  """
  def __init__(self, server, user_login, pass_login, logger_name, http_port=80, rpc_timeout=8):
    self.server = server
    self.base_url = 'http://%s:%s' % (self.server.ipaddr, http_port)
    self.api_url = self.base_url + '/command-api'
    self.user_login = user_login
    self.pass_login = pass_login
    self.logger = logging.getLogger(logger_name)
    self.http_port = http_port
    self.rpc_timeout = rpc_timeout
    self.req_id = 0
    self.acl_name = 'SNMP-ACCESS'
    self.last_acl = list()

  def get_api_req(self, cmds):
    """ CLIコマンドのリストをAPIに渡して取得するリクエストを返す
    """
    # リクエストするデータを作成
    # http://www.arista.com/assets/data/docs/Manuals/QuickStart-Managing7150Series.pdf
    self.req_id += 1
    data = dict([('jsonrpc', '2.0'),
                 ('method', 'runCmds'), 
                 ('params', dict([('format', 'json'), ('version', 1), ('cmds', cmds),])),
                 ('id', self.req_id),
                ])
    return urllib2.Request(self.api_url, json.dumps(data), {'content-type': 'application/json', })

  def check_http_error(self, http_res, err_log):
    """ urlopen()の戻値でエラーをチェック
    """ 
    if http_res.msg != 'OK':
      raise RuntimeError("%s: %s: %s(%d)" % (
            self.__class__.__name__, self.server.ipaddr, err_log, http_res.getcode(), 
            ))
    return

  def open(self):
    """ HTTPはステートレスなので擬似的に実装
    ベーシック認証でURLを開く設定をインストール
    """
    # ベーシック認証で接続
    pass_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
    pass_mgr.add_password(None, self.base_url, self.user_login, self.pass_login)
    handler = urllib2.HTTPBasicAuthHandler(pass_mgr)
    opener = urllib2.build_opener(handler)
    urllib2.install_opener(opener)
    self.write_log(self.logger, 'info', "%s (%s): 接続します." % (self.server.ipaddr, self.server.model, ))

  def get_snmp_acl(self, **kw):
    """ SNMPアクセスリストを取得
    """
    set_last_acl = kw.get('set_last_acl', True)
    acl = list()
    cmds = ['enable', 'show ip access-lists ' + self.acl_name, ]
    # APIからのレスポンスを処理
    with closing(urllib2.urlopen(self.get_api_req(cmds), timeout=self.rpc_timeout)) as res:
      self.check_http_error(res, "ACLの取得リクエストでHTTPエラーが発生しました.")
      data = json.loads(res.read())

      # warnings: "Model 'AclList' is not a public model and is subject to change!"
      # (将来データ構造が変更される可能性あり)
      assert data['id'] == self.req_id
      acls = filter(lambda a: a['name'] == self.acl_name and a['standard'] is True, data['result'][1]['aclList'])
      if len(acls) == 1:
        for e in acls[0]['sequence']:
          m = re.match(r'^\s*permit\s+(?:host\s+)?([\d.]+)(?:/([\d.]+))?\s*$', e['text'])
          if not m: 
            self.write_log(self.logger, 'warn', "%s: ACLエントリを判別できません.: %s" % (self.server.ipaddr, e, ))
            continue
          if m.group(2):
            acl.append(IPv4Network("%s/%s" % m.groups()))
          else:
            acl.append(IPv4Network("%s" % m.group(1)))
        acl.sort()
      return acl      

  def update_snmp_acl(self, acl_diff_dict, **kw):
    """ SNMPアクセスリストを更新
    """
    if kw.get('prompt', False):
      # 確認プロンプトを表示
      reply = raw_input("変更しますか? ")
      if not re.match('\s*(y|yes|)\s*$', reply.rstrip(), re.I):
        self.write_log(self.logger, 'info', "%s: 更新をキャンセルします." % (self.server.ipaddr, ))
        self.close()
        return False

    # コマンドリストを作成
    cmds = ['enable', 'configure', 'ip access-list standard ' + self.acl_name, ]
    for n in acl_diff_dict['del']:
      cmds.append('no permit ' + n.with_prefixlen)
    for n in acl_diff_dict['add']:
      cmds.append('permit ' + n.with_prefixlen)

    cmds.append('end')

    # APIからのレスポンスを処理
    with closing(urllib2.urlopen(self.get_api_req(cmds), timeout=self.rpc_timeout)) as res:
      self.check_http_error(res, "ACLの更新リクエストでHTTPエラーが発生しました.")
      data = json.loads(res.read())
      assert data['id'] == self.req_id

      if len(data['result']) != len(cmds) or filter(len, data['result']):
        # 正常に更新されている場合は、コマンドリスト内のコマンドと同数の空の辞書になっている
        self.write_log(self.logger, 'debug', data['result'])
        self.write_log(self.logger, 'error', "%s: ACLの更新リクエストを実行できませんでした." % (self.server.ipaddr, ))
        self.close()
        return False
      
      # 更新後のACLを取得して返す
      return self.get_snmp_acl(set_last_acl=False)

  def save_exit_config(self, **kw):
    """ 保存
    """
    if kw.get('prompt', False) and not re.match('\s*(y|yes|)\s*$', raw_input("保存しますか? ").rstrip(), re.I): 
      # ロールバック処理はできないので一旦削除して元のACLに戻す
      self.write_log(self.logger, 'info', "%s: 元のACLに戻します." % (self.server.ipaddr, ))        
      cmds = ['enable', 
              'configure', 
              'no ip access-list standard ' + self.acl_name, 
              'ip access-list standard ' + self.acl_name, 
              ]
      for n in self.last_acl:
        cmds.append('permit ' + n.with_prefixlen)
      cmds.append('end')

      # APIからのレスポンスを処理
      with closing(urllib2.urlopen(self.get_api_req(cmds), timeout=self.rpc_timeout)) as res:
        res = self.get_api_res(cmds)
        self.check_http_error(res, "ACLの更新リクエストでHTTPエラーが発生しました.")

    # write memory をリクエスト
    with closing(urllib2.urlopen(self.get_api_req(['enable', 'write memory',]), timeout=self.rpc_timeout)) as res:
      self.check_http_error(res, "コンフィグ保存リクエストでHTTPエラーが発生しました.しました.")
      self.write_log(self.logger, 'debug', "%s: コンフィグ保存しました." % (self.server.ipaddr, ))

  def close(self):
    """ セッション終了
    """
    self.write_log(self.logger, 'debug', "%s: セッションを閉じました." % (self.server.ipaddr, ))


