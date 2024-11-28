FROM debian:buster AS builder

RUN apt-get update
RUN apt-get install -y \
        apt-utils libelf-dev build-essential libssl-dev python3 \
        gdb autoconf libtool git automake bzip2 dh-autoreconf openssl procps

RUN mkdir /build
RUN mkdir /build/ovs

COPY . /build/ovs/
COPY ./utilities/docker/debian/build-kernel-modules.sh /build-kernel-modules.sh
RUN /build-kernel-modules.sh

COPY ./start.sh /start.sh
COPY ./port.sh /port.sh
COPY ./vswitchd/vswitch.ovsschema /usr/share/openvswitch/vswitch.ovsschema
COPY ./utilities/docker/create_ovs_db.sh /etc/openvswitch/create_ovs_db.sh
COPY ./utilities/docker/ovs-override.conf /etc/depmod.d/openvswitch.conf


FROM debian:buster

COPY --from=builder /usr/lib/x86_64-linux-gnu/libssl.so.1.1  /usr/lib/x86_64-linux-gnu/libssl.so.1.1
COPY --from=builder /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1  /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1
COPY --from=builder /usr/lib/x86_64-linux-gnu/libatomic.so.1  /usr/lib/x86_64-linux-gnu/libatomic.so.1
COPY --from=builder /usr/local/lib  /usr/local/lib
COPY --from=builder /usr/local/sbin  /usr/local/sbin
RUN /sbin/ldconfig

COPY --from=builder /start.sh /start.sh
COPY --from=builder /port.sh /port.sh
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /usr/share/openvswitch/vswitch.ovsschema /usr/share/openvswitch/vswitch.ovsschema
COPY --from=builder /etc/openvswitch/create_ovs_db.sh /etc/openvswitch/create_ovs_db.sh
RUN /etc/openvswitch/create_ovs_db.sh

COPY --from=builder /etc/depmod.d/openvswitch.conf /etc/depmod.d/openvswitch.conf



ENV PATH="$PATH:/usr/local/share/openvswitch/scripts"

VOLUME ["/var/log/openvswitch", "/var/lib/openvswitch",\
 "/var/run/openvswitch", "/etc/openvswitch"]
ENTRYPOINT ["/start.sh"]