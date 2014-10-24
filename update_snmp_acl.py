#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" ネットワーク機器の設定を変更するデモ用スクリプト

- 対象機器のSNMPアクセスリストを更新します

- 機器ごとのsysDescrを取得してから機種に対応するAPIで接続
-- cisco, brocade: telnet 
-- juniper: netconf
-- arista: eapi

 $ python update_snmp_acl.py -h
 usage: update_snmp_acl.py [-h] [-i]

 optional arguments:
   -h, --help         show this help message and exit
   -i, --interactive  show confirmation prompt (default: False)

- オプション '-i', '--interactive': 設定変更と保存前に確認プロンプトを表示
- 保存しなかった場合:
-- telnet: いったんCLIに切り替える (エスケープで処理に戻る)
-- netconf: ロールバック
-- eapi: ロールバック (変更前のACLを再投入)

"""

# 設定変更対象機器のIPアドレス
agent_ipaddrs = ('192.168.11.207', '192.168.11.101', '192.168.11.102', '192.168.11.106', )

# SNMPアクセスを許可するネットワーク
snmp_mgr_networks = ('172.25.8.0/24', '172.31.30.0/24', '192.168.11.0/24', '10.0.0.1/32', )

import sys
from os.path import *
import re
import hashlib
import logging
import getpass
import argparse
import traceback
from ipaddr import IPv4Network

from pysnmp_sess_v2c import *
import cm_agent

# ロギング設定
logger_name =basename(sys.argv[0])[:-3]
logger = logging.getLogger(logger_name)
logger.setLevel(logging.DEBUG)
# レベルdebug(or higher)をファイルに出力
flh = logging.FileHandler('./%s.log' % (logger_name, ))
flh.setLevel(logging.DEBUG)
flh.setFormatter(logging.Formatter('%(asctime)s %(name)s: [%(levelname)s] %(message)s'))
logger.addHandler(flh)
# レベルinfo(or higher)を標準エラーに出力
clh = logging.StreamHandler()
clh.setLevel(logging.INFO)
clh.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(clh)

# パスワードのハッシュ: 標準入力から取得する文字列のハッシュと比較する
pass_login_hash = '28c07f568eab870144ba7c57777460a9'
pass_enable_hash = '5c2fde453c5aac10a2d78dafe08e5b54'

def get_passwords():
  """標準入力から取得するパスワードをチェック
  """
  #return 'iw2014', 'IW2014'
  def check_password(prompt, hash):
    pass_plain = getpass.getpass(prompt=prompt).strip()
    m = hashlib.md5()
    m.update(pass_plain)
    return m.hexdigest() == hash and pass_plain or None

  while True:
    pass_login = check_password('ログインパスワードを入力:', pass_login_hash)
    if pass_login: break
    print 'no match!'
  while True:
    pass_enable = check_password('イネーブルパスワードを入力:', pass_enable_hash)
    if pass_enable: break
    print 'no match!'

  return pass_login, pass_enable


def get_agent(ipaddr):
  """取得するsysDescrの情報に対応する機器のオブジェクトを返す (arista|brocade|cisco|juniper)
  """
  m = re.search('(arista|brocade|cisco|juniper)', snmpget_sysdescr(ipaddr), re.I)
  if m:
    return getattr(cm_agent, m.group(1).lower().title())(ipaddr)
  else:
    raise ValueError("%s: 機種を特定できませんでした." % (ipaddr))


def run_sess(ipaddr, logger, pass_login, pass_enable, new_acl, prompt):
  """管理対象機器のipaddrにアクセスして設定を更新する
  """
  try:
    # 機種を特定する
    agent = get_agent(ipaddr)
  except (ValueError, PysnmpSessV2cError), e:
    # 特定できなかった場合は終了
    logger.error("%s: %s" % (e.__class__.__name__, str(e)))
    return
  # 機種ごとに対応するAPIを使ってアクセス
  sess = agent.get_sess(pass_login, pass_enable, logger.name)
  try:
    # セッション開始
    sess.open()
    # 設定されているACLとの差分を取得
    current_acl = sess.get_snmp_acl()
    acl_diff_dict = dict()
    acl_diff_dict['add'] = list(set(new_acl) - set(current_acl))
    acl_diff_dict['del'] = list(set(current_acl) - set(new_acl))

    # 新しいACLとの差分がある場合
    if filter(len, acl_diff_dict.values()):
      logger.info("%s: 変更前のACL: %s" % (ipaddr, ", ".join([n.with_prefixlen for n in current_acl])))
      updated_acl = sess.update_snmp_acl(acl_diff_dict, prompt=prompt)
      # 更新キャンセルまたはエラーの場合
      if not updated_acl and getattr(sess, 'closed', True): return
      # 更新された設定を保存
      logger.info("%s: 変更後のACL: %s" % (ipaddr, ", ".join([n.with_prefixlen for n in updated_acl])))
      sess.save_exit_config(prompt=prompt)

    # 新しいACLと一致していた場合
    else:
      logger.info("%s: ACLは更新済です." % (ipaddr, ))

    # セッション終了
    sess.close()

  except Exception, e:
    logger.debug(traceback.format_exc())
    logger.error("%s: %s: セッションの実行に失敗しました." % (sess.__class__.__name__, str(e.__class__), )) 


def main():
  # 確認プロンプトを表示するためのオプション指定を処理
  parser = argparse.ArgumentParser()
  parser.add_argument('-i', '--interactive', action='store_true', dest='prompt',
                      help='show confirmation prompt (default: False)' )
  prompt = vars(parser.parse_args())['prompt']

  try:
    # パスワード情報を取得
    pass_login, pass_enable = get_passwords()
    # SNMPアクセスを許可するネットワークのIPアドレスをIPv4Networkオブジェクトに変換
    new_acl = map(IPv4Network, snmp_mgr_networks)  

    logger.info("開始します.")
    for ipaddr in agent_ipaddrs:
      # 機器ごとに接続して設定を変更
      run_sess(ipaddr, logger, pass_login, pass_enable, new_acl, prompt)

  except KeyboardInterrupt:
    print ""
    logger.warn("処理が中断されました.")
    sys.exit()

  logger.info("終了しました.")

if __name__ == '__main__':
  main()

