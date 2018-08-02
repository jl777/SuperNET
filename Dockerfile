# Happening in a well-defined setting the Docker builds should be somewhat
# more reproducible than builds relying on the local workstation environment.
# Hence we're going to use the Docker build as the reference one.
# CI and local builds might be considered a second tier build optimizations.
# 
# docker build --tag mm2 .

FROM ubuntu:17.10

RUN \
    apt-get update &&\
    apt-get install -y git libcurl4-openssl-dev build-essential wget pax libleveldb-dev &&\
    # https://rust-lang-nursery.github.io/rust-bindgen/requirements.html#debian-based-linuxes
    apt-get install -y llvm-3.9-dev libclang-3.9-dev clang-3.9 &&\
    apt-get clean

#Cmake 3.12.0 supports multi-platform -j option, it allows to use all cores for concurrent build to speed up it
RUN wget https://cmake.org/files/v3.12/cmake-3.12.0-rc2-Linux-x86_64.sh && \
    chmod +x cmake-3.12.0-rc2-Linux-x86_64.sh && \
    ./cmake-3.12.0-rc2-Linux-x86_64.sh --skip-license --exclude-subdir --prefix=/usr && \
    rm -rf cmake-3.12.0-rc2-Linux-x86_64.sh

RUN \
    wget -O- https://sh.rustup.rs > /tmp/rustup-init.sh &&\
    sh /tmp/rustup-init.sh -y --default-toolchain stable &&\
    rm -f /tmp/rustup-init.sh

ENV PATH="/root/.cargo/bin:${PATH}"

# It seems that bindgen won't prettify without it:
RUN rustup component add rustfmt-preview

COPY . /mm2

# The number of Docker layers is limited AFAIK,
# so here we have a couple of configuration actions packed into a single step.
RUN cd /mm2 &&\
    # Put the version into the file, allowing us to easily use it from different Docker steps and from Rust.
    export MM_VERSION=`echo "$(git tag -l --points-at HEAD)"` &&\
    # If we're not in a CI-release environment then set the version to "UNKNOWN".
    if [ -z "$MM_VERSION" ]; then export MM_VERSION=UNKNOWN; fi &&\
    echo "MM_VERSION is $MM_VERSION" &&\
    echo -n "$MM_VERSION" > MM_VERSION &&\
    # `nproc --all` is "the number of processing units available".
    nproc --all > /tmp/THREAD_COUNT

RUN cd /mm2 && cargo build

RUN cd /mm2 &&\
    git submodule update --init --recursive

RUN mkdir /mm2/build && cd /mm2/build &&\
    cmake -DMM_VERSION="$(cat /mm2/MM_VERSION)" -j `cat /tmp/THREAD_COUNT` ..

RUN cd /mm2/build &&\
    cmake --build . --target marketmaker-testnet -j `cat /tmp/THREAD_COUNT`

RUN cd /mm2/build &&\
    cmake --build . --target marketmaker-mainnet -j `cat /tmp/THREAD_COUNT`

RUN cd /mm2/build &&\
    ln iguana/exchanges/marketmaker-testnet /usr/local/bin/ &&\
    ln iguana/exchanges/marketmaker-mainnet /usr/local/bin/

CMD marketmaker-testnet
