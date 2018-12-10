FROM ubuntu:18.04
USER root
RUN apt-get update && apt-get install -y rinetd curl libcurl3-gnutls libcurl4-openssl-dev gdb dnsutils iproute2 libboost-dev libboost-system-dev

RUN useradd -u 111 jenkins
USER jenkins
WORKDIR /usr/mm/etomic_build/client
CMD rm -rf DB && ./client