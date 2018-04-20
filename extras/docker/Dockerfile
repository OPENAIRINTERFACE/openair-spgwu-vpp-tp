FROM ubuntu:xenial AS build-env

RUN mkdir /src && \
    apt-get update && apt-get dist-upgrade -yy && apt install -yy build-essential sudo
ADD . /src/vpp
RUN cd /src/vpp && \
    make UNATTENDED=yes install-dep && \
    make pkg-deb V=1

FROM ubuntu:xenial
WORKDIR /
RUN apt-get update && apt-get dist-upgrade -yy && \
    apt-get install -yy liburcu4 libmbedcrypto0 libmbedtls10 libmbedx509-0 libnuma1 python python-cffi
COPY --from=build-env /src/vpp/build-root/*deb /
RUN dpkg -i *deb
ENTRYPOINT /usr/bin/vpp
