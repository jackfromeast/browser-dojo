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
    file \
    ninja-build

# Ninja needs python3 while building v8, however, the default python3.6 will cause error with ninja script
RUN ln -s /usr/bin/python2.7 /usr/bin/python
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 1

# Get depot_tools
RUN git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
ENV PATH=/build/depot_tools:$PATH
RUN gclient

# Check out the V8 source code
## We might encounter the following error during gclient sync command
## Related to: invalid cross-device link
## Reference: https://groups.google.com/a/chromium.org/g/chromium-dev/c/Sa3_-7tKR0E
ENV GCLIENT_SUPPRESS_GIT_VERSION_WARNING=1
RUN cd /build/v8 && fetch v8 &&\ 
    cd v8 &&\
    ./build/install-build-deps.sh --unsupported &&\
    git checkout 6dc88c191f5ecc5389dc26efa3ca0907faef3598 &&\
    gclient sync -D

WORKDIR /build/v8/v8

# Copy the diff file
COPY ./oob.diff /build/
RUN chmod 644 /build/oob.diff
RUN git apply /build/oob.diff


RUN ./tools/dev/v8gen.py x64.release
## IF ARGS.GN FILE IS PROVIDED
COPY ./args.gn /build/v8/v8/out.gn/x64.release/
RUN chmod 644 /build/v8/v8/out.gn/x64.release/args.gn
RUN ninja -C out.gn/x64.release d8
