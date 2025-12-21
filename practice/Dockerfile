# Reference: https://github.com/kevoreilly/CAPEv2/issues/617

# LTS Ubuntu as base image
FROM ubuntu:24.04

RUN apt update && sudo apt upgrade -y

RUN apt update && apt install -y \
    curl \
    gcc \
    g++ \
    make \
    libmagic1 \
    p7zip-full \
    git \
    tcpdump \
    sudo

# create user cape
WORKDIR /practice
# git clone capev2 instead 
RUN chmod +x cape2.sh

# start kvm-qemu.sh

# share volume to volume folder and workdir set

# add configs and installation script

# expose ports

# ENTRYPOINT ["/bin/sh"]
