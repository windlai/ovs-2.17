FROM debian:buster AS builder

RUN apt-get update
RUN apt-get install -y \
        apt-utils libelf-dev build-essential libssl-dev python3 \
        gdb autoconf libtool git automake bzip2 dh-autoreconf openssl procps


FROM builder AS build

RUN mkdir /build
RUN mkdir /build/ovs

COPY . /build/ovs/
COPY ./utilities/docker/debian/build-kernel-modules.sh /build-kernel-modules.sh
RUN /build-kernel-modules.sh


COPY ./start.sh /start.sh
COPY ./port.sh /port.sh
COPY ./vswitchd/vswitch.ovsschema /usr/share/openvswitch/vswitch.ovsschema

COPY ./utilities/docker/create_ovs_db.sh /etc/openvswitch/create_ovs_db.sh
RUN /etc/openvswitch/create_ovs_db.sh

ENV PATH="$PATH:/usr/local/share/openvswitch/scripts"

COPY ./utilities/docker/ovs-override.conf /etc/depmod.d/openvswitch.conf

COPY ./utilities/docker/start-ovs /bin/start-ovs
VOLUME ["/var/log/openvswitch", "/var/lib/openvswitch",\
 "/var/run/openvswitch", "/etc/openvswitch"]
ENTRYPOINT ["/start.sh"]