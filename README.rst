.. NOTE(stephenfin): If making changes to this file, ensure that the
   start-after/end-before lines found in 'Documentation/intro/what-is-ovs'
   are kept up-to-date.

============
Open vSwitch
============

What's here?
------------

The main components of this distribution are:

- This branch is forked from openvswitch/ovs branch-2.17.
- Target is that build a ovs docker and run in SONiC device.
- To build the docker use the following command::

   docker build -t openvswitch/ovs:2.17_debian --build-arg DISTRO=debian --progress=plain --no-cache -f Dockerfile .

- The docker runs ovsdb-server and ovs-vswitchd in the same container.
- When "docker stop *ovs*", automatically "ovs-ofctl del-flows *bridge*".

Run the docker in SONiC::

   docker run --privileged -d -ti --net=host --name ovs openvswitch/ovs:2.17_debian

Add SONiC Ethernet port to bridge, default bridge name is ovs-acl::

   docker exec ovs /port.sh
   docker exec ovs /port.sh *bridge*


SONiC supports flow field:

- priofiry <1-10000>: priority of the same matched in_port should be different
- matched in_port: a flow in SONiC must be specified with the field
- matched dl_vlan with dl_type 0x8100: limit by SONiC ASCI, does not support mask
- matched nw_src with dl_type 0x800: support mask
- matched nw_dst with dl_type 0x800: support mask
- matched nw_proto
- matched tp_src
- matched tp_dst
- matched icmp_type: include IPv6
- matched icmp_code: include IPv6
- matched ipv6_src with dl_type 0x86dd
- matched ipv6_dst with dl_type 0x86dd
- action dop
- action output: redirect to a single port

SONiC flow example::

   docker exec ovs ovs-ofctl add-flow wind priority=1,in_port=1,dl_type=0x8100,dl_vlan=777,actions=output:3
   docker exec ovs ovs-ofctl add-flow wind priority=2,in_port=1,dl_type=0x800,nw_src=192.168.100.1/24,nw_dst=192.168.100.2,actions=drop
   docker exec ovs ovs-ofctl add-flow wind priority=3,in_port=1,dl_type=0x800,nw_proto=17,tp_src=53,tp_dst=54,actions=2
   docker exec ovs ovs-ofctl add-flow wind priority=4,in_port=1,dl_type=0x800,nw_proto=1,icmp_type=8,icmp_code=0,actions=drop
   docker exec ovs ovs-ofctl add-flow wind priority=5,in_port=1,dl_type=0x86dd,nw_proto=58,icmp_type=8,icmp_code=0,actions=output:3
   docker exec ovs ovs-ofctl add-flow wind priority=6,in_port=1,dl_type=0x86dd,ipv6_src=2001::1,ipv6_dst=2001::2/64,actions=drop


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

Files under the xenserver directory are licensed on a file-by-file basis.
Refer to each file for details.

Files lib/sflow*.[ch] are licensed under the terms of either the
Sun Industry Standards Source License 1.1, that is available at:
        http://host-sflow.sourceforge.net/sissl.html
or the InMon sFlow License, that is available at:
        http://www.inmon.com/technology/sflowlicense.txt

Contact
-------

bugs@openvswitch.org
