cm_demo
=======
Internet Week 2014 で担当する運用自動化に関するセッションのデモ用に作ったプログラムです。
SNMP、Telnet、NETCONF、REST API等でネットワーク機器に接続して、SNMPアクセスリストを変更、保存する一連の処理を、Pythonで実装したスクリプトです。

Python2.7で動作確認済みです。
以下のパッケージに依存しています。

 - ipaddr
 - pysnmp
 - pexpect
 - ncclient
 - lxml
 - junos-eznc

```
$ python update_snmp_acl.py -h
usage: update_snmp_acl.py [-h] [-i]

optional arguments:
 -h, --help         show this help message and exit
 -i, --interactive  show confirmation prompt (default: False)
```
