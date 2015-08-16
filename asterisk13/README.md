# Asterisk 13 + FreePBX 13 Install & Fail2Ban
These scripts automate the installation. You will be asked a few questions and at the end you will need to secure MySQL.

## Install
1. wget https://raw.githubusercontent.com/rfriedlein/AudioVideo/master/asterisk13/install_asterisk.sh

2. wget https://raw.githubusercontent.com/rfriedlein/AudioVideo/master/asterisk13/install_fail2ban.sh

3. chown +x *.sh

4. ./install_asterisk.sh |tee asterisk13_install.log

5. ./install_fail2ban.sh |tee fail2ban_install.log
