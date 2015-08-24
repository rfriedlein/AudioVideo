#Upgrade and install some apps
apt-get update && apt-get upgrade -y

wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
sh -c 'echo "deb http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list'

wget -q -O - http://archive.getdeb.net/getdeb-archive.key | sudo apt-key add -
sudo sh -c 'echo "deb http://archive.getdeb.net/ubuntu trusty-getdeb apps" >> /etc/apt/sources.list.d/getdeb.list'

apt-get update

apt-get install -y php5 php-pear php5-json php5-json google-chrome-stable libboost1.53 snmpd snmp-mibs-downloader php5-mcrypt php5-ldap oracle-java6-installer idle eclipse gparted vim tasksel nfs-common nfs4-acl-tools qemu-kvm libvirt-bin ubuntu-vm-builder bridge-utils virt-manager virt-install itop htop iftop ngrep tcpdump screenlets conky-all lm-sensors hddtemp ttf-mscorefonts-installer

# Install MythTV
apt-get install git build-essential qt4-dev-tools yasm uuid-dev libfreetype6-dev libmp3lame-dev libxinerama-dev libtag1-dev make gcc g++ libexiv2-dev libdbd-mysql-perl libnet-upnp-perl libdbi-perl python-urlgrabber python-mysqldb libqt4-sql-mysql

cd /opt/

git clone git://github.com/MythTV/mythtv.git

git pull

./configure

make && make install

#make dir's
mkdir /media/Movies
mkdir /media/Music
mkdir /media/TV
mkdir /media/games
mkdir /media/data

#add nfs mounts
echo "
# Store NFS Shares
<SETNASADDRESS>:/mnt/movies/movies/Movies/	/media/Movies	nfs	auto,noatime,nolock,bg,nfsvers=3,intr,tcp,actimeo=1800 0 0
<SETNASADDRESS>:/mnt/nfs_data03/data/Music/	/media/Music	nfs	auto,noatime,nolock,bg,nfsvers=3,intr,tcp,actimeo=1800 0 0
<SETNASADDRESS>:/mnt/nfs_tv02/data/TV/		/media/TV	nfs	auto,noatime,nolock,bg,nfsvers=3,intr,tcp,actimeo=1800 0 0
<SETNASADDRESS>:/mnt/nfs_data03/data/Games/       /media/games    nfs     auto,noatime,nolock,bg,nfsvers=3,intr,tcp,actimeo=1800 0 0
<SETNASADDRESS>:/mnt/nfs_data03/data/Storage/	/media/data	nfs	auto,noatime,nolock,bg,nfsvers=3,intr,tcp,actimeo=1800 0 0" >> /etc/fstab

#mount NFS 

mount -a

#add host file things

# DNS
echo "domain rfriedlein.com
search rfriedlein.com
options rotate timeout:1 attempts:4
nameserver 192.168.1.3
nameserver 8.8.8.8" > /etc/resolv.conf

# update time and date via ntp
ntpdate pool.ntp.org

