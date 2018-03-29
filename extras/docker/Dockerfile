FROM ubuntu:xenial AS build-env

RUN mkdir /src && \
    apt-get update && apt-get dist-upgrade -yy && apt install -yy build-essential sudo
ADD . /src/vpp
RUN cd /src/vpp && \
    make UNATTENDED=yes install-dep && \
    make bootstrap V=1 && \
    make build-release V=1 && \
    make install DESTDIR=/src/vpp/build && \
    ls -lR build && \
    ldd /src/vpp/build/usr/bin/vpp

FROM ubuntu:xenial
WORKDIR /
RUN apt-get update && apt-get dist-upgrade -yy && \
    apt-get install -yy liburcu6
COPY --from=build-env /src/vpp/build /
ENTRYPOINT /usr/bin/vpp