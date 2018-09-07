FROM centos:7.5.1804

ENV GOSU_VERSION 1.10
ENV GOSU_ARCH amd64
ENV GOSU_URL https://github.com/tianon/gosu/releases/download
ENV GOSU_APP ${GOSU_URL}/${GOSU_VERSION}/gosu-${GOSU_ARCH}
ENV GOSU_ASC ${GOSU_URL}/${GOSU_VERSION}/gosu-${GOSU_ARCH}.asc

# Setup required system packages
RUN set -x \
    && yum install -y epel-release \
    && yum clean all \
    && rm -rf /var/cache/yum

RUN set -x \
    && yum install -y \
       iproute \
       jq \
       leveldb \
       python36 \
    && ln -s /usr/bin/python36 /usr/bin/python3 \
    && yum clean all \
    && rm -rf /var/cache/yum

# gosu
RUN set -x \
    && adduser -m bitcoin \
    && chown bitcoin:bitcoin /home/bitcoin \
	&& curl -o /usr/local/bin/gosu -SL ${GOSU_APP} \
	&& curl -o /usr/local/bin/gosu.asc -SL ${GOSU_ASC} \
	&& export GNUPGHOME="$(mktemp -d)" \
	&& gpg --keyserver ha.pool.sks-keyservers.net --recv-keys \
        B42F6819007F00F88E364FD4036A9C25BF357DD4 \
	&& gpg --batch --verify /usr/local/bin/gosu.asc /usr/local/bin/gosu \
	&& rm -rf "$GNUPGHOME" /usr/local/bin/gosu.asc \
	&& chmod +x /usr/local/bin/gosu \
    && gosu nobody true

COPY . /usr/src/cb-electrum-server
COPY docker-entrypoint.sh /

# Build Electrum server
RUN set -x \
    && cd /usr/src/cb-electrum-server \
    && curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py \
    && python3 get-pip.py \
    && rm -f get-pip.py \
    && python3 setup.py build \
    && python3 setup.py install

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["electrum_server"]