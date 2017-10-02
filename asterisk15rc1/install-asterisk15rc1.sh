#!/bin/bash

##################################
## rfrieldein.com 10/02/2017    ##
## robyn@rfriedlein.com         ##
## v1.0                         ##
## Install Asterisk 15 RC1      ##
##################################

export ASTERISK_DB_PW=`dd if=/dev/urandom bs=1 count=32 2>/dev/null | base64 - | cut -c2-18`

if [ "$(id -u)" != "0" ]; then
	   echo "This script must be run as root" 1>&2
	      exit 1
      fi

      #Install some stuff
      apt-get update && apt-get upgrade -y
      apt-get install build-essential gcc wget curl git libssl-dev libncurses5-dev libreadline-dev libreadline6-dev libnewt-dev libxml2-dev linux-headers-$(uname -r) libsqlite3-dev libiksemel-dev libsqlite3-dev libjansson-dev uuid-dev libxslt1-dev liburiparser-dev pkg-config subversion libspandsp-dev libiksemel-utils libiksemel3 libasound2-dev libogg-dev libvorbis-dev libcurl4-openssl-dev libical-dev libneon27-dev libsrtp0-dev automake libtool autoconf unixodbc-dev uuid mpg123 sqlite3 bison flex php7.0 php7.0-curl php7.0-cli php7.0-mysql php-pear php-db php7.0-gd curl sox openssh-server apache2 dahdi -y

      export DEBIAN_FRONTEND=noninteractive
      apt-get install mysql-server mysql-client mysql-common libmysqlclient-dev -y
      mysql-conn_test

      cd /usr/src/

      #Install Mysql ODBC Connector
      wget  https://dev.mysql.com/get/Downloads/Connector-ODBC/5.3/mysql-connector-odbc-5.3.9-linux-ubuntu16.04-x86-64bit.tar.gz
      tar xzvf mysql-connector-odbc-5.3.9-linux-ubuntu16.04-x86-64bit.tar.gz
      cd mysql-connector-odbc*
      mv libmyodbc5a.so /usr/lib/x86_64-linux-gnu/odbc/
      mv libmyodbc5w.so /usr/lib/x86_64-linux-gnu/odbc/ 

      #Install pjproject
      wget http://www.pjsip.org/release/2.7/pjproject-2.7.tar.bz2
      tar -xjvf pjproject-2.7.tar.bz2
      cd pjproject-2.7
       ./configure --prefix=/usr --enable-shared --disable-sound --disable-resample --disable-video --disable-opencore-amr CFLAGS='-O2 -DNDEBUG'
       make dep && make && make install 
       ldconfig

       #Install libpri
       cd /usr/src/
       wget http://downloads.asterisk.org/pub/telephony/libpri/libpri-1.6.0.tar.gz
       tar zxvf libpri*
       cd /usr/src/libpri*
       make && make install

       #Install jansson 
       cd /usr/src/
       git clone https://github.com/akheron/jansson.git
       cd /usr/src/jansson
       autoreconf -i
       ./configure
       make
       make install

       #Asterisk Extra Sounds
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
       wget http://downloads.asterisk.org/pub/telephony/asterisk/asterisk-15.0.0-rc1.tar.gz
       tar zxvf asterisk*
       cd /usr/src/asterisk*
       ./contrib/scripts/get_mp3_source.sh
       ./configure && make menuselect && make && make install && make config && make samples

       useradd -m asterisk
       chown asterisk. /var/run/asterisk
       chown -R asterisk. /etc/asterisk
       chown -R asterisk. /var/{lib,log,spool}/asterisk
       chown -R asterisk. /usr/lib/asterisk

       sed -i 's/\(^upload_max_filesize = \).*/\120M/' /etc/php5/apache2/php.ini
       cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf_orig
       sed -i 's/^\(User\|Group\).*/\1 asterisk/' /etc/apache2/apache2.conf
       service apache2 restart


       echo "When asked for database credentials, use these."
       echo "Database username: asteriskuser"
       echo "Database password: $ASTERISK_DB_PW"
       echo "Be sure to save these!"

       /etc/init.d/asterisk stop

       ./start_asterisk start

       ln -s /var/lib/asterisk/moh /var/lib/asterisk/mohmp3

       service asterisk stop
       service asterisk start

