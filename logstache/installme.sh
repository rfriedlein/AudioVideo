root@logs:/home/rob# cat installme.sh 
#!/bin/bash
# This scriot installs Redis stable version, Logstash 1.2.2, 
# Elasticsearch 1.2.0 and Kibana Git verision.
# 05/24/2014
# Author Rob Friedlein
#
# Be sure tho chomd +x this script and run it with 2>&1 | tee script-log.txt
#
#!/bin/bash
INSTDIR="/usr/src/"
WWWDIR="/var/www"
IP_ADDR=$(getent hosts `hostname` | awk '{print $1}')

echo "Installing Redis"
#Install Prerequisites
apt-get update
apt-get -y install python-software-properties
add-apt-repository ppa:webupd8team/java
apt-get update
apt-get -y install gcc build-essential make git oracle-java7-installer apache2 php5 unzip
apt-get -y remove openjdk-7-jre-headless

#Install Redis
cd $INSTDIR
wget http://download.redis.io/releases/redis-stable.tar.gz
tar xzf redis-stable.tar.gz
cd redis-stable
make MALLOC=libc
cp src/redis-server /usr/local/bin/
cp src/redis-cli /usr/local/bin/
cp redis.conf /etc/redis.conf
sed -i 's/daemonize no/daemonize yes/g' /etc/redis.conf
sed -i 's/logfile ""/logfile "\/var\/log\/redis-server.log"/g' /etc/redis.conf

cd $INSTDIR
echo "Starting Redis Server"
redis-server /etc/redis.conf
redis-cli ping

#Install Logstash
echo "Installing Logstash"
mkdir /opt/logstash /etc/logstash
cd /opt/logstash
wget https://download.elasticsearch.org/logstash/logstash/logstash-1.2.2-flatjar.jar

echo "Creating Logstash configs"
#Logstache Redis config file
echo "
input { stdin { } }
output {
  stdout { codec => rubydebug }
  redis { host => "$IP_ADDR" data_type => "list" key => "logstash" }
}" >  /etc/logstash/logstash-redis.conf

#Logstache Apache 2 logs
echo "
input {
  file {
    path => "/var/log/apache2/*access.log"
    type => "apache"
  }
}
 
filter {
  if [type] == "apache" {
    grok {
      pattern => "%{COMBINEDAPACHELOG}"
    }
  }
}
 
output {
  redis { host => "$IP_ADDR" data_type => "list" key => "logstash" }
}" > /etc/logstash/logstash-shipper.conf

#Logstache iptables
mkdir -p /usr/share/grok/patterns
echo "
# Source : http://cookbook.logstash.net/recipes/config-snippets/
NETFILTERMAC %{COMMONMAC:dst_mac}:%{COMMONMAC:src_mac}:%{ETHTYPE:ethtype}
ETHTYPE (?:(?:[A-Fa-f0-9]{2}):(?:[A-Fa-f0-9]{2}))
IPTABLES1 (?:IN=%{WORD:in_device} OUT=(%{WORD:out_device})? MAC=%{NETFILTERMAC} SRC=%{IP:src_ip} DST=%{IP:dst_ip}.*(TTL=%{INT:ttl})?.*PROTO=%{WORD:proto}?.*SPT=%{INT:src_port}?.*DPT=%{INT:dst_port}?.*)
IPTABLES2 (?:IN=%{WORD:in_device} OUT=(%{WORD:out_device})? MAC=%{NETFILTERMAC} SRC=%{IP:src_ip} DST=%{IP:dst_ip}.*(TTL=%{INT:ttl})?.*PROTO=%{INT:proto}?.*)
IPTABLES (?:%{IPTABLES1}|%{IPTABLES2})" > /usr/share/grok/patterns/iptables

#Add iptables to Logstache conf
echo "

input {
  file {
    path => [ "/var/log/syslog" ]
    type => "iptables"
  }
}
 
filter {
  if [type] == "iptables" {
    grok {
      patterns_dir => "/usr/share/grok/patterns/iptables"
      pattern => "%{IPTABLES}"
    }
  }
}
 
output {
  # Check that the processed line matched against grok iptables pattern
  if !("_grokparsefailure" in [tags]) {
    redis { host => "$IP_ADDR" data_type => "list" key => "logstash" }
  }
}" >> /etc/logstash/logstash-shipper.conf

#Logstach syslog
echo "

input {
  file {
    path => [ "/var/log/*.log", "/var/log/messages", "/var/log/syslog" ]
    type => "syslog"
  }
}
 
output {
  redis { host => "$IP_ADDR" data_type => "list" key => "logstash" }
}" >> /etc/logstash/logstash-shipper.conf

java -Xmx256m -jar /opt/logstach/logstash-1.2.2-flatjar.jar agent -f /etc/logstash/logstash-redis.conf

echo "
#! /bin/sh
#
#	/etc/rc.d/init.d/logstash
#
#	Starts Logstash as a daemon
#
# chkconfig: 2345 20 80
# description: Starts Logstash as a daemon
# pidfile: /var/run/logstash-agent.pid

### BEGIN INIT INFO
# Provides: logstash
# Required-Start: $local_fs $remote_fs
# Required-Stop: $local_fs $remote_fs
# Default-Start: 2 3 4 5
# Default-Stop: S 0 1 6
# Short-Description: Logstash
# Description: Starts Logstash as a daemon.
# Modified originally from https://gist.github.com/2228905#file_logstash.sh

### END INIT INFO

# Amount of memory for Java
#JAVAMEM=256M

# Location of logstash files
LOCATION=/opt/logstash

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
DESC="Logstash Daemon"
NAME=java
DAEMON=$(which java)
CONFIG_DIR=/opt/logstash/logstash.conf
LOGFILE=/opt/logstash/logstash.log
JARNAME=logstash-monolithic.jar
#ARGS="-Xmx$JAVAMEM -Xms$JAVAMEM -jar ${JARNAME} agent --config ${CONFIG_DIR} --log ${LOGFILE} --grok-patterns-path ${PATTERNSPATH}"
ARGS="-jar ${JARNAME} agent --config ${CONFIG_DIR} --log ${LOGFILE}"
SCRIPTNAME=/etc/init.d/logstash
PIDFILE=/var/run/logstash.pid
base=logstash

# Exit if the package is not installed
if [ ! -x "$DAEMON" ]; then
{
  echo "Couldn\'t find $DAEMON"
  exit 99
}
fi

. /etc/init.d/functions

#
# Function that starts the daemon/service
#
do_start()
{
  cd $LOCATION && \
  ($DAEMON $ARGS &) \
  && success || failure
}

set_pidfile()
{
  pgrep -f "$DAEMON[[:space:]]*$ARGS" > $PIDFILE
}

#
# Function that stops the daemon/service
#
do_stop()
{
  pid=`cat $PIDFILE`
                       if checkpid $pid 2>&1; then
                           # TERM first, then KILL if not dead
                           kill -TERM $pid >/dev/null 2>&1
                           usleep 100000
                           if checkpid $pid && sleep 1 &&
                              checkpid $pid && sleep $delay &&
                              checkpid $pid ; then
                                kill -KILL $pid >/dev/null 2>&1
                                usleep 100000
                           fi
                        fi
                        checkpid $pid
                        RC=$?
                        [ "$RC" -eq 0 ] && failure $"$base shutdown" || success $"$base shutdown"

}

case "$1" in
  start)
    echo -n "Starting $DESC: "
    do_start
    touch /var/lock/subsys/$JARNAME
    set_pidfile
    ;;
  stop)
    echo -n "Stopping $DESC: "
    do_stop
    rm /var/lock/subsys/$JARNAME
    rm $PIDFILE
    ;;
  restart|reload)
    echo -n "Restarting $DESC: "
    do_stop
    do_start
    touch /var/lock/subsys/$JARNAME
    set_pidfile
    ;;
  status)
    status -p $PIDFILE
    ;;
  *)
    echo "Usage: $SCRIPTNAME {start|stop|status|restart}" >&2
    exit 3
    ;;
esac

echo
exit 0" > /etc/init.d/logstash

echo "Starting Logstasah"
/etc/init.d/logstash start

echo "Installing Elasticsearch"
#Install Elasticsearch 
wget https://download.elasticsearch.org/elasticsearch/elasticsearch/elasticsearch-1.2.0.deb 
dpkg -i elasticsearch-1.2.0.deb
sed -i 's/#http.port: 9200/http.port: 9200/g' /etc/elasticsearch/elasticsearch.yml

echo "Starting Elasticsearch"
/etc/init.d/elasticsearch restart

echo "Installing Kibana"
#Finally, let’s install Kibana
cd $INSTDIR
wget http://download.elasticsearch.org/kibana/kibana/kibana-latest.zip
unzip kibana-latest.zip
mkdir $WWWDIR/kibana
mv $INSTDIR/kibana-latest/* $WWWDIR/kibana/
chown -R www-data:www-data $WWWDIR

echo "You may now login to your stack at http://"$IP_ADDR"/kibana"
