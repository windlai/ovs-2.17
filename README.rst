.. NOTE(stephenfin): If making changes to this file, ensure that the
   start-after/end-before lines found in 'Documentation/intro/what-is-ovs'
   are kept up-to-date.

============
Open vSwitch
============


What's here?
------------

The main components of this distribution are:

- When packet is upcall with action output to controller, send the packet to nDPI.
- After nDPI parsing, sends parsed APP protocol (Facebook, FTP, Youtube, etc.) to specified KAFAK.
- The KAFKA server should be launched with `goflow2 <https://github.com/nocsysmonitor/goflow2>`__ environment.


Test procedure
--------------------------------------

- Export related KAFKA variable before starting ovs-vswitchd::

   export KAFKA_SAMPLER=192.168.254.232
   export KAFKA_BROKER=192.168.254.232:9092

- Start ovs and add bridge/ports::

   ovs-ctl start
   ovs-vsctl add-br br0
   ovs-vsctl add-port br0 veth_l0
   ip link set veth_l0 up

- Add a flow with action output to controller::

   ovs-ofctl add-flow br0 priority=2,in_port=1,dl_type=0x800,nw_dst=192.168.40.136,actions=controller

- Inject a packet matched the flow, and check result of KAFKA/clickhouse.

License
-------

The following is a summary of the licensing of files in this distribution.
As mentioned, Open vSwitch is licensed under the open source Apache 2 license.
Some files may be marked specifically with a different license, in which case
that license applies to the file in question.


Files under the datapath directory are licensed under the GNU General Public
License, version 2.

File build-aux/cccl is licensed under the GNU General Public License, version 2.

The following files are licensed under the 2-clause BSD license.
    include/windows/getopt.h
    lib/getopt_long.c
    lib/conntrack-tcp.c

The following files are licensed under the 3-clause BSD-license
    include/windows/netinet/icmp6.h
    include/windows/netinet/ip6.h
    lib/strsep.c

Files lib/sflow*.[ch] are licensed under the terms of either the
Sun Industry Standards Source License 1.1, that is available at:
        http://host-sflow.sourceforge.net/sissl.html
or the InMon sFlow License, that is available at:
        http://www.inmon.com/technology/sflowlicense.txt


