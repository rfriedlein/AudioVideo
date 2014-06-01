#!/bin/bash
# 06/01/2014
# rob@rfriedlein.com
# This script install and builds a basic beaver config
# for apache2 logs on Ubuntu.

apt-get update

apt-get install python-pip git -y

pip install git+git://github.com/josegonzalez/beaver.git#egg=beaver

# Create Logstash Init Script
(
cat <<'EOF'
#!/bin/bash -
### BEGIN INIT INFO
# Provides:          beaver
# Required-Start:    $local_fs $remote_fs $network
# Required-Stop:     $local_fs $remote_fs $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start up the Beaver at boot time
# Description:       Enable Log Sender provided by beaver.
### END INIT INFO


BEAVER_NAME='beaver'
BEAVER_CMD='beaver -t redis -c /etc/beaver/beaver.conf'
RUNDIR='/var/run/beaver'
BEAVER_PID=${RUNDIR}/logstash_beaver.pid
BEAVER_USER='root'
LOGDIR='/var/log/beaver'
BEAVER_LOG=${LOGDIR}/logstash_beaver.log


PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
export PATH
IFS=$' \t\n'
export IFS

BEAVER_BIN="$(which "${BEAVER_NAME}")"

[ -r /etc/init.d/functions ] && . /etc/init.d/functions
[ -r /lib/lsb/init-functions ] && . /lib/lsb/init-functions
[ -r "/etc/default/${BEAVER_NAME}" ] && . "/etc/default/${BEAVER_NAME}"

do_start() {
    test -f "${BEAVER_BIN}" || exit 0
    if is_up
    then
        echo $'Log Sender server daemon already started.'
        return 0
    fi
    mkdir -p $RUNDIR
    chown $BEAVER_USER $RUNDIR
    mkdir -p $LOGDIR
    chown $BEAVER_USER $LOGDIR
    echo -n $"Log Sender server daemon: ${BEAVER_NAME}"
    su - "${BEAVER_USER}" -s '/bin/bash' -c "${BEAVER_CMD} >> ${BEAVER_LOG} 2>&1 & echo \$! > ${BEAVER_PID}"
    echo '.'
}

do_stop() {
    test -f "${BEAVER_BIN}" || exit 0
    if ! is_up
    then
        echo $'Log Sender server daemon already stopped.'
        return 0
    fi
    echo -n $"Stopping Log Sender server daemon: ${BEAVER_NAME}"
    do_kill
    while is_up
    do
        echo -n '.'
        sleep 1
    done
    echo '.'
}

beaver_pid() {
    tail -1 "${BEAVER_PID}" 2> /dev/null
}

is_up() {
    PID="$(beaver_pid)"
    [ x"${PID}" != x ] && ps -p "${PID}" -o comm h 2> /dev/null | grep -qFw "${BEAVER_NAME}"
}

do_kill() {
    PID="$(beaver_pid)"
    [ x"${PID}" != x ] && su - "${BEAVER_USER}" -c "kill -TERM ${PID}"
}

do_restart() {
    test -f "${BEAVER_BIN}" || exit 0
    do_stop
    sleep 1
    do_start
}

do_status() {
    test -f "${BEAVER_BIN}" || exit 0
    if is_up
    then
        echo "${BEAVER_NAME} is running."
        exit 0
    else
        echo "${BEAVER_NAME} is not running."
        exit 1
    fi
}

do_usage() {
    echo $"Usage: $0 {start | stop | restart | force-reload | status}"
    exit 1
}

case "$1" in
start)
    do_start
    exit "$?"
    ;;
stop)
    do_stop
    exit "$?"
    ;;
restart|force-reload)
    do_restart
    exit "$?"
    ;;
status)
    do_status
    ;;
*)
    do_usage
    ;;
esac
EOF
) | tee /etc/init.d/beaver

# Make logstash executable
chmod +x /etc/init.d/beaver

# Enable logstash start on bootup
update-rc.d beaver defaults 96 04

mkdir -p /etc/beaver/conf.d

echo "Setting up beaver for different appliance type"
echo "Your appliance type:"
echo "(example - apache or firewall)"
echo -n "Enter your appliance type and press enter: "
read yourappliancename
echo "You entered ${red}$yourhostip${NC}"
echo "Setting up beaver, we need the redis server ip or fqdn"
echo "Your redis host ip or fqdn:"
echo "(example - 172.22.1.21 or host.domain.com)"
echo -n "Enter your host ip or fqdn and press enter: "
read yourredishost
echo "You entered ${red}$yourredishost${NC}"

tee -a /etc/beaver/beaver.conf <<EOF
[beaver]
redis_url: redis://$yourredishost:6379/0
redis_namespace: logstash:$yourappliancename:production
queue_timeout: 43200 
logstash_version: 1
format: string

[/var/log/apache2/*.log]
tags: $yourappliancename,production
type: $yourappliancename:production"
EOF

/etc/init.d/beaver start
