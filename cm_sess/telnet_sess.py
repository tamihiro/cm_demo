# -*- coding: utf-8 -*-

import sys
import re
import logging
import pexpect
from ipaddr import IPv4Network

from base import SessBase

class TelnetSess(SessBase):
  """telnetセッション用クラス
  """
  def __init__(self, device, pass_login, pass_enable, logger_name, 
               user_login=None, telnet_port=23, telnet_timeout=8, screen_dump=None):
    self.device = device
    self.pass_login = pass_login
    self.pass_enable = pass_enable
    self.logger = logging.getLogger(logger_name)
    if user_login:
      self.user_login = user_login
    self.telnet_port = telnet_port
    self.telnet_timeout = telnet_timeout
    self.logfile = screen_dump
    self.need_priv = False
    self.deact_pager = False
    self.pass_prompt = ".*Password:"
    self.acl_name = 'SNMP-ACCESS'
    self.closed = True

    # 機種依存の設定
    assert self.device.model in ('juniper', 'brocade', 'cisco', )
    if self.device.model == "juniper":
      self.unpriv_prompt = "\r\n%s@[-\w]+>" % (self.user_login, )
      self.config_prompt = "\r\n%s@[-\w]+#" % (self.user_login, )
      self.add_acl_cmd = lambda n: "set policy-options prefix-list %s %s" % (self.acl_name, n.with_prefixlen, )
      self.del_acl_cmd = lambda n: "delete policy-options prefix-list %s %s" % (self.acl_name, n.with_prefixlen, )
      self.linebreak = "\n"
    if self.device.model == "brocade":
      self.need_priv = True
      self.deact_pager = True
      self.unpriv_prompt = "\r\ntelnet@[-\w]+>"
      self.priv_prompt = "\r\ntelnet@[-\w]+#"
      self.config_prompt = "\r\ntelnet@[-\w]+\(config.*\)#"
      self.config_acl_cmd = "ip access-list standard " + self.acl_name
      self.add_acl_cmd = lambda n: "permit " + n.with_prefixlen
      self.del_acl_cmd = lambda n: "no " + self.add_acl_cmd(n)
      self.linebreak = "\r\n"
    if self.device.model == "cisco":
      self.need_priv = True
      self.deact_pager = True
      self.unpriv_prompt = "\r\n[-\w]+>"
      self.priv_prompt = "\r\n[-\w]+#"
      self.config_prompt = "\r\n[-\w]+\(config.*\)#"
      self.config_acl_cmd = "ip access-list standard " + self.acl_name
      self.add_acl_cmd = lambda n: "permit " + n.with_hostmask.replace('/', ' ')
      self.del_acl_cmd = lambda n: "no " + self.add_acl_cmd(n)
      self.linebreak = "\n"

  def sendline(self, line):
    if hasattr(self, 'child'):
      getattr(self, 'child').send(line + self.linebreak)

  def open(self):
    """ログインしてイネーブルモードへ移行
    """
    self.child = pexpect.spawn("telnet -4%s %s %d" % (
         hasattr(self, 'user_login') and " -l " + self.user_login or "", 
         self.device.ipaddr,
         self.telnet_port, 
         ))
    self.child.timeout = self.telnet_timeout
    if self.logfile:
      try:
        self.child.logfile = open(self.logfile, 'a')
      except:
        self.write_log(self.logger, 'warn', "%s: ファイルをオープンできません." % (self.logfile, ))
        
    self.child.expect(self.pass_prompt)
    self.sendline(self.pass_login)
    self.child.expect(self.unpriv_prompt)
    if self.need_priv:
      self.sendline("enable")
      self.child.expect(self.pass_prompt)
      self.sendline(self.pass_enable)
      self.child.expect(self.priv_prompt)
    if self.deact_pager:
      self.sendline("term len 0")
      self.child.expect(self.priv_prompt)
    self.closed = False
    self.write_log(self.logger, 'info', "%s (%s): ログインしました." % (self.device.ipaddr, self.device.model))
  
  def start_config(self):
    """ コンフィグモードへ移行
    """
    return getattr(self, '_start_config_' + self.device.model)()

  def _start_config_juniper(self):
    self.sendline("configure")
    self.child.expect(self.config_prompt)

  def _start_config_brocade(self):
    self.sendline("configure t")
    self.child.expect(self.config_prompt)

  def _start_config_cisco(self):
    return self._start_config_brocade()

  def get_snmp_acl(self, **kw):
    """ SNMPアクセスリストを取得
    """
    # コンフィグモードでshowコマンドを実行するときはTrue
    config_mode=kw.get('config_mode', False)
    acl = list()
    for m in getattr(self, '_gen_snmp_acl_' + self.device.model)(config_mode):
      if not m: continue
      if m.group(2):
        acl.append(IPv4Network("%s/%s" % m.groups()))
      else:
        acl.append(IPv4Network("%s" % m.group(1)))
    acl.sort()
    return acl

  def _gen_snmp_acl_brocade(self, config_mode):
    cmd = "show access-list name %s | inc ^_+sequence" % (self.acl_name, )
    self.sendline(cmd)
    self.child.expect(config_mode and self.config_prompt or self.priv_prompt)
    for l in self.child.before.split('\r\n')[1:]:
      if len(l.strip()) == 0: continue
      m = re.match(r"^\s*sequence\s+\d+\s+permit\s+(?:host\s+)?([\d.]+)(?:\s+([\d.]+))?\s*$", l)
      if not m:
        self.write_log(self.logger, 'warn', "%s: ACLエントリを判別できません.: %s" % (self.device.ipaddr, l, ))
        continue
      yield m

  def _gen_snmp_acl_juniper(self, config_mode):
    cmd = "show%s policy-options prefix-list %s | no-more" % ("" if config_mode else " configuration", self.acl_name, )
    self.sendline(cmd)
    self.child.expect(config_mode and self.config_prompt or self.unpriv_prompt)
    for l in self.child.before.split('\r\n')[1:]:
      if l.strip() in (cmd.strip(), '[edit]') or len(l) == 0: continue
      m = re.match(r"^\s*([\d.]+)/(\d+);\s*$", l)
      if not m:
        self.write_log(self.logger, 'warn', "%s: ACLエントリを判別できません.: %s" % (self.device.ipaddr, l, ))
        continue
      yield m

  def _gen_snmp_acl_cisco(self, config_mode):
    cmd = "%s show ip access-lists %s | inc [0-9]+_permit_" % (config_mode and "do" or "", self.acl_name, )
    self.sendline(cmd)
    self.child.expect(config_mode and self.config_prompt or self.priv_prompt)
    for l in self.child.before.split('\r\n')[1:]:
      if len(l.strip()) == 0: continue
      m = re.match(r"^\s*\d+\s+permit\s+([\d.]+)(?:,\s+wildcard\s+bits\s+([\d.]+))?\b", l)
      if not m:
        self.write_log(self.logger, 'warn', "%s: %s: ACLエントリを判別できません.: %s" % (self.device.ipaddr, l, ))
        continue
      yield m

  def update_snmp_acl(self, acl_dict, **kw):
    """ SNMPアクセスリストを更新
    """
    if kw.get('prompt', False):
      # 確認プロンプトを表示
      reply = raw_input("変更しますか? ")
      if not re.match('\s*(y|yes|)\s*$', reply.rstrip(), re.I):
        self.write_log(self.logger, 'info', "%s: 更新をキャンセルします." % (self.device.ipaddr, ))
        self.close()
        return False

    self.start_config()
    if hasattr(self, 'config_acl_cmd'):
      self.sendline(self.config_acl_cmd)
      self.child.expect(self.config_prompt)      

    for which, n in [ (which, n) for which in acl_dict for n in acl_dict[which]]:
      self.sendline(getattr(self, which + '_acl_cmd')(n))
      self.child.expect(self.config_prompt)

    return self.get_snmp_acl(config_mode=True)

  def save_exit_config(self, **kw):
    """ 保存してコンフィグモードを終了
    """
    if kw.get('prompt', False):
      # 確認プロンプトを表示
      while True:
        reply = raw_input("保存しますか? ")
        if re.match('\s*(y|yes|)\s*$', reply.rstrip(), re.I): break
        self.write_log(self.logger, 'debug', "%s: CLIを開始します." % (self.device.ipaddr, ))
        print ""
        print "Telnetセッションのコンフィグモードを開始します."
        print "CLIでの作業が済んだら '^]' で終了してください."
        print ""
        sys.stdout.write(self.child.after)
        sys.stdout.flush()
        self.child.interact()
        print ""
        print "Telnetセッションからスクリプトの処理に復帰します."
        print ""
        self.write_log(self.logger, 'debug', "%s: スクリプトの処理に復帰します." % (self.device.ipaddr, ))
    getattr(self, '_save_exit_config_' + self.device.model)()
    self.write_log(self.logger, 'debug', "%s: コンフィグ保存しました." % (self.device.ipaddr, ))

  def _save_exit_config_juniper(self):
    self.sendline("commit and-quit")
    self.child.expect(self.unpriv_prompt)

  def _save_exit_config_brocade(self):
    self.sendline("write mem")
    i = self.child.expect([self.config_prompt, self.priv_prompt])  
    if i == 0:
      self.sendline("end")
      self.child.expect(self.priv_prompt)

  def _save_exit_config_cisco(self):
    self.sendline("")
    i = self.child.expect([self.config_prompt, self.priv_prompt])  
    if i == 0:
      self.sendline("do write mem")
      self.child.expect(self.config_prompt)
      self.sendline("end")
    else:
      self.sendline("write mem")
    self.child.expect(self.priv_prompt)

  def close(self):
    """ セッション終了
    """
    if self.closed: return
    self.sendline("exit")
    i = self.child.expect([self.unpriv_prompt, pexpect.EOF])  
    if i == 0:
      self.sendline("exit")
      self.child.expect(pexpect.EOF)
    self.write_log(self.logger, 'debug', "%s: セッションを閉じました." % (self.device.ipaddr, ))
    self.closed = True
