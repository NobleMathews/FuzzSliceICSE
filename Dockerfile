FROM ubuntu:20.04
ARG DEBIAN_FRONTEND=noninteractive
ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8

# note that we need to install a newer version of cmake through a pass
RUN apt-get update --fix-missing
RUN apt-get install -y --no-install-recommends llvm-11* clang-11* gdb git curl zsh tmux wget libxml2 libarchive13 autoconf vim pkg-config bison

RUN cp /usr/bin/llvm-profdata-11 /usr/bin/llvm-profdata && cp /usr/bin/llvm-cov-11 /usr/bin/llvm-cov && cp /usr/bin/clang-11 /usr/bin/clang

# GIT STUFF
RUN git config --global core.fileMode false && \
    git config --global diff.ignoreSubmodules dirty && \
    git config --global core.autocrlf input && \
    git config --global --add oh-my-zsh.hide-status 1 && \
    git config --global --add oh-my-zsh.hide-dirty 1

# PIP
ENV PIP_ROOT_USER_ACTION=ignore

RUN apt-get update -y \
    && apt-get install -y python3-pip
RUN pip install --upgrade pip

COPY . /StaticSlicer

# BEAR
RUN apt-get install -y bear
# SRCML
RUN arch=$(arch | sed s/aarch64/arm64/ | sed s/x86_64/amd64/) && \
    dpkg -i /StaticSlicer/tools/libssl1.1.${arch}.deb
# This won't work for arm64 - need to build from source
RUN wget http://131.123.42.38/lmcrs/v1.0.0/srcml_1.0.0-1_ubuntu20.04.deb && \
    dpkg -i srcml_1.0.0-1_ubuntu20.04.deb
# RATS
RUN git clone https://github.com/andrew-d/rough-auditing-tool-for-security
WORKDIR /rough-auditing-tool-for-security
RUN ./configure && make && make install

#RUN cp /usr/bin/llvm-profdata-11 /usr/bin/llvm-profdata && cp /usr/bin/llvm-cov-11 /usr/bin/llvm-cov && cp /usr/bin/clang-11 /usr/bin/clang
#RUN cp /usr/bin/clang-11 /usr/bin/clang

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

# Setup for test repos
RUN apt-get install -y libevent-dev libssl-dev

# openssl
WORKDIR /StaticSlicer/test_lib/openssl
RUN cp ./Configure ./configure

# openssh-portable
WORKDIR /StaticSlicer/test_lib/openssh-portable
RUN apt-get install -y automake
RUN autoreconf

# tmux
WORKDIR /StaticSlicer/test_lib/tmux
RUN sh autogen.sh

WORKDIR /StaticSlicer
RUN pip install -r requirements.txt