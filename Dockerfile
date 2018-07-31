# Happening in a well-defined setting the Docker builds should be somewhat
# more reproducible than builds relying on the local workstation environment.
# Hence we're going to use the Docker build as the reference one.
# CI and local builds might be considered a second tier build optimizations.
# 
# docker build --tag mm2 .

FROM ubuntu:17.10
RUN apt-get update && apt-get install -y git libcurl4-openssl-dev build-essential wget pax libleveldb-dev && apt-get clean
RUN wget https://cmake.org/files/v3.10/cmake-3.10.3-Linux-x86_64.sh && \
    chmod +x cmake-3.10.3-Linux-x86_64.sh && \
    ./cmake-3.10.3-Linux-x86_64.sh --skip-license --exclude-subdir --prefix=/usr && \
    rm -rf cmake-3.10.3-Linux-x86_64.sh

COPY . /mm2

RUN cd /mm2 &&\
    git submodule update --init --recursive

RUN mkdir /mm2/build && cd /mm2/build &&\
    export MM_VERSION=`echo "$(git tag -l --points-at HEAD)"` &&\
    # If we're not in a CI-release environment then set the version to "dev".
    if [ -z "$MM_VERSION" ]; then export MM_VERSION=dev; fi &&\
    echo "MM_VERSION is $MM_VERSION" &&\
    cmake -DMM_VERSION="$MM_VERSION" ..

RUN cd /mm2/build &&\
    cmake --build . --target marketmaker-testnet

RUN cd /mm2/build &&\
    cmake --build . --target marketmaker-mainnet

RUN cd /mm2/build &&\
    ln iguana/exchanges/marketmaker-testnet /usr/local/bin/ &&\
    ln iguana/exchanges/marketmaker-mainnet /usr/local/bin/

CMD marketmaker-testnet
