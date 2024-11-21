#!/bin/bash

export PATH=$PATH:/usr/local/share/openvswitch/scripts
#ovs-ctl --system-id=ramdom start

name="ovs-acl"

if [ -z "$1" ]; then
  name="ovs-acl"
else
  name=$1
fi

ovs-vsctl add-br $name
#ofport=1

for f in $(ip -br l | grep Ethernet | sed 's/Ethernet//g'|sort -n | awk '$1 !~ "lo|vir|wl" { print $1}')
do
  #echo "nic:" $f
  #ovs-vsctl add-port wind Ethernet0 -- set Interface Ethernet0 ofport_request=1
  #ip address show Ethernet0 | grep ether | awk '{print $2}'

  #echo $f
  #macaddr=$(ip address show $portname | grep ether | awk '{print $2}')
  #ovs-vsctl add-port $1 Ethernet$f -- set Interface $f ofport_request=$ofport
  ovs-vsctl add-port $name Ethernet$f -- set Interface Ethernet$f ofport_request=$f
  #echo "ovs-vsctl add-port "$name" Ethernet"$f" -- set Interface "$f" ofport_request="$ofport
  echo "ovs-vsctl add-port "$name" Ethernet"$f" -- set Interface Ethernet"$f" ofport_request="$f
  #((ofport+=1))
done

