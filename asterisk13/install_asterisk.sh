#!/bin/bash

apt-get update && apt-get upgrade -y
apt-get install build-essential wget curl git libssl-dev libncurses5-dev libreadline-dev libreadline6-dev libnewt-dev libxml2-dev linux-headers-$(uname -r) libsqlite3-dev libiksemel-dev libmyodbc libsqlite3-dev libjansson-dev uuid-dev libxslt1-dev liburiparser-dev pkg-config subversion libspandsp-dev libiksemel-utils libiksemel3 libasound2-dev libogg-dev libvorbis-dev libcurl4-openssl-dev libical-dev libneon27-dev libsrtp0-dev automake libtool autoconf unixodbc-dev uuid libmysqlclient-dev mpg123 sqlite3 mysql-client bison flex php5 php5-curl php5-cli php5-mysql php-pear php-db php5-gd curl sox openssh-server apache2 mysql-server dahdi -y

#install pjproject
cd /usr/src/
wget http://www.pjsip.org/release/2.4/pjproject-2.4.tar.bz2
tar -xjvf pjproject-2.4.tar.bz2
cd pjproject-2.4
 ./configure --prefix=/usr --enable-shared --disable-sound --disable-resample --disable-video --disable-opencore-amr CFLAGS='-O2 -DNDEBUG'
make dep && make && make install 
ldconfig

#install libpri
cd /usr/src/
wget http://downloads.asterisk.org/pub/telephony/libpri/libpri-1.4-current.tar.gz
tar zxvf libpri*
cd /usr/src/libpri*
make && make install

mkdir -p /var/lib/asterisk/sounds
cd /var/lib/asterisk/sounds
wget http://downloads.asterisk.org/pub/telephony/sounds/asterisk-extra-sounds-en-wav-current.tar.gz
tar xfz asterisk-extra-sounds-en-wav-current.tar.gz
rm -f asterisk-extra-sounds-en-wav-current.tar.gz
# Wideband Audio download
wget http://downloads.asterisk.org/pub/telephony/sounds/asterisk-extra-sounds-en-g722-current.tar.gz
tar xfz asterisk-extra-sounds-en-g722-current.tar.gz
rm -f asterisk-extra-sounds-en-g722-current.tar.gz

#build asterisk
cd /usr/src/
wget http://downloads.asterisk.org/pub/telephony/asterisk/asterisk-13-current.tar.gz
tar zxvf asterisk*
cd /usr/src/asterisk*
./contrib/scripts/get_mp3_source.sh
./configure && make menuselect && make && make install && make config && make samples

#FreePBX
pear uninstall db
pear install db-1.7.14

cd /usr/src/
git clone https://github.com/akheron/jansson.git
cd /usr/src/jansson
autoreconf -i
./configure
make
make install
cd /usr/src/
wget http://mirror.freepbx.org/modules/packages/freepbx/freepbx-13.0-latest.tgz
tar vxfz freepbx-13.0-latest.tgz

useradd -m asterisk
chown asterisk. /var/run/asterisk
chown -R asterisk. /etc/asterisk
chown -R asterisk. /var/{lib,log,spool}/asterisk
chown -R asterisk. /usr/lib/asterisk
rm -rf /var/www/html

sed -i 's/\(^upload_max_filesize = \).*/\120M/' /etc/php5/apache2/php.ini
cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf_orig
sed -i 's/^\(User\|Group\).*/\1 asterisk/' /etc/apache2/apache2.conf
service apache2 restart

export ASTERISK_DB_PW=`dd if=/dev/urandom bs=1 count=32 2>/dev/null | base64 - | cut -c2-18`

mysqladmin -u root -p create asterisk
mysqladmin -u root -p create asteriskcdrdb

mysql -u root -p -e "GRANT ALL PRIVILEGES ON asterisk.* TO asteriskuser@localhost IDENTIFIED BY '${ASTERISK_DB_PW}';"
mysql -u root -p -e "GRANT ALL PRIVILEGES ON asteriskcdrdb.* TO asteriskuser@localhost IDENTIFIED BY '${ASTERISK_DB_PW}';"
mysql -u root -p -e "flush privileges;"

cd /usr/src/freepbx

./start_asterisk start
./install_amp --installdb --username=asteriskuser --password=${ASTERISK_DB_PW}
fwconsole chown
fwconsole ma installall
fwconsole reload
fwconsole ma refreshsignatures
amportal chown

ln -s /var/lib/asterisk/moh /var/lib/asterisk/mohmp3
amportal restart

