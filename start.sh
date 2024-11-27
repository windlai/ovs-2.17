#!/bin/bash

export PATH=$PATH:/usr/local/share/openvswitch/scripts
#ovs-ctl --system-id=ramdom start

mkdir -p /usr/local/var/run/openvswitch

echo "mkdir -p /usr/local/var/run/openvswitch"

cleanup() {
    echo "Container stopped, performing cleanup..."
    for br in $(ovs-vsctl show | grep Bridge | awk '{print $2}')
        do
            echo "br="$br
            ovs-ofctl del-flows $br
            echo "ovs-ofctl del-flows "$br
        done
}

trap 'cleanup' TERM INT

ovsdb-server --pidfile /etc/openvswitch/conf.db \
        -vconsole:emer -vsyslog:err -vfile:info \
        --remote=punix:/usr/local/var/run/openvswitch/db.sock \
        --private-key=db:Open_vSwitch,SSL,private_key \
        --certificate=db:Open_vSwitch,SSL,certificate \
        --bootstrap-ca-cert=db:Open_vSwitch,SSL,ca_cert \
        --log-file=/var/log/openvswitch/ovsdb-server.log \
        --no-chdir &
echo "ovsdb-server"

ovs-vswitchd --pidfile -vconsole:emer \
        -vsyslog:err -vfile:info --mlockall --no-chdir \
        --log-file=/var/log/openvswitch/ovs-vswitchd.log &
echo "ovs-vswitchd"
wait