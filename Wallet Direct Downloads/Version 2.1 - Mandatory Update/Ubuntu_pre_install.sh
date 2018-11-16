#!/bin/sh

# Ubuntu Xenial pre-installation script.
# This will fail on Bionic unless you enable
# the Xenial repositories. Create a file in
# /etc/apt/sources.list.d/xenial.list:
# deb http://archive.ubuntu.com/ubuntu xenial-updates main universe
# deb http://security.ubuntu.com/ubuntu xenial-security main universe

sudo apt-get update
sudo apt-get dist-upgrade
sudo apt-get install libboost-system1.58.0 libboost-filesystem1.58.0 libboost-program-options1.58.0 libboost-thread1.58.0 libboost-chrono1.58.0 libminiupnpc10 libzmq5 libevent-2.0-5 libevent-pthreads-2.0-5 libcurl4-openssl-dev
