#!/bin/bash

##################################
## rfrieldein.com 07/31/2015    ##
## robyn@rfriedlein.com         ##
## Install fail2ban             ##
##################################

if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

echo "messages => security,notice,warning,error" >> /etc/asterisk/logger_logfiles_additional.conf

asterisk -rx "logger reload"

apt-get update && apt-get -y install fail2ban

(
cat <<'EOF'

[asterisk-iptables]
# if more than 4 attempts are made within 6 hours, ban for 24 hours
enabled  = true
filter   = asterisk
action   = iptables-allports[name=ASTERISK, protocol=all]
              sendmail[name=ASTERISK, dest=dest@email.here, sender=fail2ban@address.here]
logpath  = /var/log/asterisk/messages
maxretry = 4
findtime = 21600
bantime = 86400

EOF

) | tee >> /etc/fail2ban/jail.conf

cd /etc/fail2ban/filter.d
mv asterisk.conf ../asterisk.conf.orig

(
cat << "EOF"
# Fail2Ban configuration file
#
#
# $Revision: 251 $
#

[INCLUDES]

# Read common prefixes. If any customizations available -- read them from
# common.local
before = common.conf


[Definition]

#_daemon = asterisk

# Option:  failregex
# Notes.:  regex to match the password failures messages in the logfile. The
#          host must be matched by a group named "host". The tag "<HOST>" can
#          be used for standard IP/hostname matching and is only an alias for
#          (?:::f{4,6}:)?(?P<host>\S+)
# Values:  TEXT
#
# Asterisk 1.8 uses Host:Port format which is reflected here

failregex = NOTICE.* .*: Registration from '.*' failed for '<HOST>:.*' - Wrong password
            NOTICE.* .*: Registration from '.*' failed for '<HOST>:.*' - No matching peer found
            NOTICE.* .*: Registration from '.*' failed for '<HOST>:.*' - No matching peer found
            NOTICE.* .*: Registration from '.*' failed for '<HOST>:.*' - Username/auth name mismatch
            NOTICE.* .*: Registration from '.*' failed for '<HOST>:.*' - Device does not match ACL
            NOTICE.* .*: Registration from '.*' failed for '<HOST>:.*' - Peer is not supposed to register
            NOTICE.* .*: Registration from '.*' failed for '<HOST>:.*' - ACL error (permit/deny)
            NOTICE.* .*: Registration from '.*' failed for '<HOST>:.*' - Device does not match ACL
            NOTICE.* .*: Registration from '\".*\".*' failed for '<HOST>:.*' - No matching peer found
            NOTICE.* .*: Registration from '\".*\".*' failed for '<HOST>:.*' - Wrong password
            NOTICE.* <HOST> failed to authenticate as '.*'$
            NOTICE.* .*: No registration for peer '.*' \(from <HOST>\)
            NOTICE.* .*: Host <HOST> failed MD5 authentication for '.*' (.*)
            NOTICE.* .*: Failed to authenticate user .*@<HOST>.*
            NOTICE.* .*: <HOST> failed to authenticate as '.*'
            NOTICE.* .*: <HOST> tried  to authenticate with nonexistent user '.*'
            VERBOSE.*SIP/<HOST>-.*Received incoming SIP connection from unknown peer
   
# Option:  ignoreregex
# Notes.:  regex to ignore. If this regex matches, the line is ignored.
# Values:  TEXT
#
ignoreregex =
EOF
) | tee  /etc/fail2ban/filter.d/asterisk.conf

service fail2ban restart

echo " fail2ban will secure asterisk from unwanted visitors"
echo "If more than 4 attempts are made within 6 hours, ban for 24 hours"
echo "Change settings in /etc/fail2ban/jail.conf"
