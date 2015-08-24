#!/bin/bash

# Install MythTV
apt-get install git build-essential qt4-dev-tools yasm uuid-dev libfreetype6-dev libmp3lame-dev libxinerama-dev libtag1-dev make gcc g++ libexiv2-dev libdbd-mysql-perl libnet-upnp-perl libdbi-perl python-urlgrabber python-mysqldb libqt4-sql-mysql

cd /opt/

git clone git://github.com/MythTV/mythtv.git

git pull

./configure

make && make install

