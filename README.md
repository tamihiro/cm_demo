cm_demo
=======
Internet Week 2014 で担当する運用自動化に関するセッションのデモ用に作ったプログラムです。
SNMP、Telnet、NETCONF、REST API等でネットワーク機器に接続して、SNMPアクセスリストを変更、保存する一連の処理を、Pythonで実装したスクリプトです。

Python2.7で動作確認済みです。
以下のパッケージをpip installする必要があります(依存パッケージもインストールされます)。

 - ipaddr
 - pysnmp
 - pexpect
 - junos-eznc

update_snmp_acl.py を実行すると、機種の異なる5台の機器に順次接続してアクセスリストを更新、保存します。

```
$ python update_snmp_acl.py -h
usage: update_snmp_acl.py [-h] [-i] [-d]

optional arguments:
  -h, --help         show this help message and exit
  -i, --interactive  show confirmation prompt (default: False)
  -d, --dump-telnet  copy telnet screen to a file (default: False)
```

update_snmp_acl_thread.py は同じ処理をマルチスレッドで実行します。

```
$ python update_snmp_acl_thread.py -h
usage: update_snmp_acl_thread.py [-h] [-d]

optional arguments:
  -h, --help         show this help message and exit
  -d, --dump-telnet  copy telnet screen to a file (default: False)
```
