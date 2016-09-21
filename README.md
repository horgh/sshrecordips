# Summary
Purpose of this program: I firewall off several ports where only whitelisted
IPs may access them. I want to automatically permit IPs that login via SSH.

This program tails the ssh auth log and records IPs as they log in. A separate
program ([iptables-manage](https://github.com/horgh/iptables-manage)) ingests
these IPs and updates the firewall.

It runs as a daemon and tails a log, typically /var/log/auth.log.
