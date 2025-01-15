FROM ubuntu:22.04

COPY sources.list /etc/apt/

RUN apt-get update && apt-get install -y \
    build-essential \
    gcc-multilib \
    git \
    gdb \
    openssl \
    libssl-dev \
    libnanomsg-dev \ 
    python3.9

WORKDIR /workdir