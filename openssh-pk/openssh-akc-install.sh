#!/bin/sh

apt-get install -y python-software-properties mlocate vim 
wget -O- http://dev.marc.waeckerlin.org/repo/PublicKey | sudo apt-key add -
sudo apt-add-repository http://dev.marc.waeckerlin.org/repo

apt-get update && apt-get upgrade

#Install patched openssh server
apt-get remove --purge openssh-server && apt-get install openssh-akc-server libpam-ldap libnss-ldap nscd

echo "AuthorizedKeysCommand /etc/ssh/ldap-keys.sh" >> /etc/ssh/sshd_config

(
cat <<'EOF'
#!/bin/bash
 
# get configuration from /etc/ldap/ldap.conf
for x in $(sed -n 's/^\([a-zA-Z_]*\) \(.*\)$/\1="\2"/p' /etc/ldap/ldap.conf); do 
    eval $x; 
done
 
OPTIONS=
case "$ssl" in
    start_tls) 
	case "$tls_checkpeer" in
	    no) OPTIONS+="-Z";;
	    *) OPTIONS+="-ZZ";;
	esac;;
esac
 
ldapsearch $OPTIONS -H ${uri} \
    -w "${bindpw}" -D "${binddn}" \
    -b "${base}" \
    '(&(objectClass=posixAccount)(uid='"$1"'))' \
    'sshPublicKey' \
    | sed -n '/^ /{H;d};/sshPublicKey:/x;$g;s/\n *//g;s/sshPublicKey: //gp' 
EOF
) | tee /etc/ssh/ldap-keys.sh

chmod +x /etc/ssh/ldap-keys.sh

echo "
base dc=coredial,dc=net
uri ldap://ldap.coredial.net:389

ssl=no

ldap_version 3
sudoers_base   ou=SUDOers,dc=coredial,dc=net
sudoers_search_filter (&(attribute=sudoRole))" >> /etc/ldap/ldap.conf

sed -i '/# and here are more per-package modules (the "Additional" block)/a session required                        pam_mkhomedir.so umask=0022 skel=/etc/skel' /etc/pam.d/common-session

service ssh restart
