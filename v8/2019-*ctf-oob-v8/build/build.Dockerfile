### Dockerfile for building the vulnerable V8 version used in *CTF 2019: oob-v8 challenge
### To Build: 
###     sudo docker build -t starctf-2019-oob-v8 -f build.Dockerfile .
FROM ubuntu:18.04

RUN mkdir -p /build/v8
WORKDIR /build

RUN apt update && apt install -yq --no-install-recommends \
    git \
    python3.8 \
    python2.7 \
    ca-certificates \
    curl \
    tar \
    xz-utils \
    build-essential \
    lsb-release \
    sudo \
    file

# Link python to python2.7
# Ninja needs python3 while building v8, however, the defualt python3.6 will cause error with ninja script
RUN ln -s /usr/bin/python2.7 /usr/bin/python
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 1

# Install GEF
RUN apt-get install gdb
RUN bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# Get depot_tools
RUN git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
ENV PATH=/build/depot_tools:$PATH
RUN gclient

# Check out the V8 source code
## We might encounter the following error during gclient sync command
## Related to: invalid cross-device link
## Reference: https://groups.google.com/a/chromium.org/g/chromium-dev/c/Sa3_-7tKR0E
RUN cd /build/v8 && fetch v8 &&\ 
    cd v8 &&\
    ./build/install-build-deps.sh &&\
    git checkout 6dc88c191f5ecc5389dc26efa3ca0907faef3598 &&\
    gclient sync -D

WORKDIR /build/v8/v8

COPY ./Chrome/oob.diff /build/
RUN chmod 644 /build/oob.diff
RUN git apply /build/oob.diff

RUN ./tools/dev/v8gen.py x64.debug
RUN chmod 644 out.gn/x64.debug/args.gn
RUN gn gen out.gn/x64.debug

RUN apt-get install ninja-build
RUN ninja -C out.gn/x64.debug d8

# Compile a release version of d8 as the debug version add some extra checks
RUN ./tools/dev/v8gen.py x64.release
RUN ninja -C out.gn/x64.release d8