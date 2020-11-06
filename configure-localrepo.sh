#! /bin/bash

interface=$(ls -la /etc/sysconfig/network-scripts/ifcfg-en* | cut -d'/' -f5 | cut -d'-' -f2)
uuid=$(cat /etc/sysconfig/network-scripts/ifcfg-$interface | grep "UUID" | cut -d'=' -f2)
staticcon=$(cat /etc/sysconfig/network-scripts/ifcfg-$interface | grep "BOOTPROTO" | cut -d'=' -f2)
mynodeip=$(cat /etc/sysconfig/network-scripts/ifcfg-$interface | grep "IPADDR" | cut -d'=' -f2)

if [[ $EUID > 0 ]]; 
then # we can compare directly with this syntax.
  echo "Please run as root/sudo"
  exit 1
else
	#change to ip static
	if [[ $staticcon == "dhcp" ]];
	then
		echo "You are using DHCP setting. Below are your details:"
		ipaddrs=$(ip a | grep "inet" | cut -d' ' -f6 | tail -2 | sed '$d')
		echo $ipaddrs
		echo -n "Enter IP Address [192.168.1.99]: "
		read ipaddr
		echo -n "Enter Netmask [255.255.255.0]: "
		read netmask
		echo -n "Enter Gateway [192.168.1.254]: "
		read gateway
		echo -n "Enter DNS1 [8.8.8.8]: "
		read dns1
		echo -n "Enter DNS2 [1.1.1.1]: "
		read dns2
	
		echo "TYPE=Ethernet
PROXY_METHOD=none
BROWSER_ONLY=no
BOOTPROTO=static
DEFROUTE=yes
IPV4_FAILURE_FATAL=no
IPV6INIT=no
NETWORKING_IPV6=no
NAME="$interface"
UUID="$uuid"
DEVICE="$interface"
#MTU=9000
ONBOOT=yes
IPADDR="$ipaddr"
NETMASK="$netmask"
GATEWAY="$gateway"
DNS1="$dns1"
DNS2="$dns2"" > /etc/sysconfig/network-scripts/ifcfg-$interface
	else 
		echo "Network already in static"
		sleep 1
	fi
	
	echo "Setting up static IP and restarting network"
	systemctl restart network
	sleep 1
	
	if ping -q -c 1 -W 1 8.8.8.8 >/dev/null; then
		echo "Internet connected!"
		sleep 1
	else
		echo "Please check internet Connection"
		sleep 1
		exit 1
	fi
	
	#selinux
	status=$(cat /etc/selinux/config | grep "SELINUX" | cut -d'=' -f2 | cut -d':' -f2 | head -n 2 | sed -r '/^\s*$/d')
	if [[ $status == "enforcing" ]];
		then
		echo "Disabling selinux - reboot required.."
		sed -i 's/enforcing/disabled/g' /etc/selinux/config /etc/selinux/config
		echo "PLEASE REBOOT LATER!"
	else
		echo "SELINUX already disabled"
	fi
	sleep 1
	
	#changing current node hostname
	echo "This is your curent hostname"
	hostname
	read -p "Change current node hostname? (y/n)?" CONT
	if [ "$CONT" = "y" ]; then
                echo -n "Enter new node Hostname [abc.com.my]: "
                read chost
                hostnamectl set-hostname ""$chost"" --static
                echo "This is final hostname status "
                hostname
	else
                echo "This is final hostname status "
                hostname
	fi
	sleep 1
	
	#setup hostname master and slave
	echo "Setting up host file.."
	
	echo -n "Enter your domain name [cloudera.com]: "
	read dmain1
	
	echo -n "Enter Master node IP address: "
	read m1ip
	echo -n "Enter Master node hostname [master-node]: "
	read m1host
    echo $m1ip"         "$m1host"."$dmain1"         "$m1host > /etc/hosts
	  
	echo -n "Enter Slave 01 IP address: "
	read s1ip
	echo -n "Enter Slave 01 hostname [slave-01-node]: "
	read s1host
    echo $s1ip"         "$s1host"."$dmain1"         "$s1host >> /etc/hosts
	echo $s1ip >> /tmp/slaveip-temp.txt
	  
	echo -n "Enter Slave 02 IP address: "
	read s2ip
	echo -n "Enter Slave 02 hostname [slave-02-node]: "
	read s2host
    echo $s2ip"         "$s2host"."$dmain1"         "$s2host >> /etc/hosts
	echo $s2ip >> /tmp/slaveip-temp.txt
	
	echo -n "Enter Slave 03 IP address: "
	read s3ip
	echo -n "Enter Slave 03 hostname [slave-03-node]: "
	read s3host
    echo $s3ip"         "$s3host"."$dmain1"         "$s3host >> /etc/hosts
	echo $s3ip >> /tmp/slaveip-temp.txt
	
	#extra local domain
	echo "172.16.1.45         centosrepo.spectrum-edge.com" >> /etc/hosts
	
	
	#disable firewalld
	echo "Disabling and stopping firewalld.."
	systemctl disable firewalld
	systemctl stop firewalld
	sleep 1

	#setting up localrepo
	touch /etc/yum.repos.d/localrepo.repo
	echo "[localrepo]
name=Spectrum Repository
baseurl=http://centosrepo.spectrum-edge.com/pub/localrepo
gpgcheck=0
enabled=1" > /etc/yum.repos.d/localrepo.repo

	mv /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bak
	mv /etc/yum.repos.d/CentOS-Sources.repo /etc/yum.repos.d/CentOS-Sources.repo.bak
	mv /etc/yum.repos.d/CentOS-CR.repo /etc/yum.repos.d/CentOS-CR.repo.bak
	mv /etc/yum.repos.d/CentOS-Vault.repo /etc/yum.repos.d/CentOS-Vault.repo.bak
	mv /etc/yum.repos.d/CentOS-Debuginfo.repo /etc/yum.repos.d/CentOS-Debuginfo.repo.bak
	mv /etc/yum.repos.d/CentOS-x86_64-kernel.repo /etc/yum.repos.d/CentOS-x86_64-kernel.repo.bak
	mv /etc/yum.repos.d/CentOS-fasttrack.repo /etc/yum.repos.d/CentOS-fasttrack.repo.bak
	mv /etc/yum.repos.d/CentOS-Media.repo /etc/yum.repos.d/CentOS-Media.repo.bak

	yum clean all
	
	echo "Installing net-tools, wget, perl and sshpass.."	
	yum -y install net-tools
	yum -y install wget
	yum -y install perl
	yum -y install openssh*
	yum -y install sshpass*
	yum -y install openssl*
	sleep 1
	
	echo "Checking mode status(Master or Slave)"
	ip1=$(sed -n '1p' /tmp/slaveip-temp.txt)
	ip2=$(sed -n '2p' /tmp/slaveip-temp.txt)
	ip3=$(sed -n '3p' /tmp/slaveip-temp.txt)
	mynodeip1=$(cat /etc/sysconfig/network-scripts/ifcfg-$interface | grep "IPADDR" | cut -d'=' -f2)
	if [[ "$mynodeip1" == "$ip1" || "$mynodeip1" == "$ip2" || "$mynodeip1" == "$ip3" ]];
	then
		echo "Current node is slave. Moving on.."
	else
		echo "Setting up passwordless SSH for HADOOP cluster.."
		rm -rf ~/.ssh/id_rsa*
		ssh-keygen -t rsa -P "" -f ~/.ssh/id_rsa

		echo -n "Enter "$ip1" root password: "
		read ip1pass
		sshpass -p $ip1pass ssh-copy-id $ip1
	
		echo -n "Enter "$ip2" root password: "
		read ip2pass
		sshpass -p $ip2pass ssh-copy-id $ip2
	
		echo -n "Enter "$ip3" root password: "
		read ip3pass
		sshpass -p $ip3pass ssh-copy-id $ip3
	fi

#	echo "Installing rpmforge repo.."
#	#check if already installed
#	rpmforgestat=$(ls /etc/yum.repos.d/ | grep "rpm" | cut -d'.' -f1 | tail -1)
#	if [[ $rpmforgestat == "rpmforge" ]];
#	then
#		echo "rpmforge repo already installed!"
#	else
#		cd /tmp
#		wget https://ftp.tu-chemnitz.de/pub/linux/dag/redhat/el7/en/x86_64/rpmforge/RPMS/rpmforge-release-0.5.3-1.el7.rf.x86_64.rpm
#		rpm -Uhv /tmp/rpmforge-release-0.5.3-1.el7.rf.x86_64.rpm
#		sleep 1
#	fi
	
	echo "Disabling IPV6.."
	#checking if already disabled
	ipv6disable=$(cat /etc/sysctl.conf | grep "lo" | cut -d'=' -f1 | cut -d'.' -f5)
	if [[ $ipv6disable == "disable_ipv6" ]];
	then
		echo "IPV6 already disabled"
	else
		echo "# disable ipv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv6.conf.enp0s3.disable_ipv6 = 1" >> /etc/sysctl.conf
		sleep 1
	fi
	
	echo "Enabling fastest mirror.."
	sed -i 's/enabled=0/enabled=1/g' /etc/yum/pluginconf.d/fastestmirror.conf /etc/yum/pluginconf.d/fastestmirror.conf
	sleep 1

	echo "Editing VM swappiness.."
	sysctl vm.swappiness=10
	sleep 1
	
	echo "Disable VM sleep mode.."
	sleepmodestat=$(cat /etc/profile | grep "powersave" | cut -d' ' -f4 | tail -1)
	if [ -z "$sleepmodestat" ]
	then
      echo "setterm -blank 0 -powersave off -powerdown 0" >> /etc/profile
	else
      echo "VM sleepmode already disabled!"
	fi
	sleep 1
	
	echo "Add user securonix"
	username=securonix
	echo -n "Please create new password for securonix user: "
	read password
	egrep "^$username" /etc/passwd >/dev/null
	if [ $? -eq 0 ]; then
		echo "User $username already exists! continuing.."
	else
		pass=$(perl -e 'print crypt($ARGV[0], "password")' $password)
		useradd -m -p "$pass" "$username"
		[ $? -eq 0 ] && echo "User has been added to system!" || echo "Failed to add a user!"
	fi
	sleep 1
	
	echo "Adding user to wheel.."
	gpasswd -a securonix wheel
	sed -i 's/#%wheel/%wheel/g' /etc/sudoers /etc/sudoers
	sleep 1

	echo "Adding directory /Securonix.."
	mkdir /Securonix
	mkdir /Securonix/install/
	mkdir /Securonix/install/SNYPR
	mkdir /Securonix/install/SNYPR/MYSQL
	mkdir /Securonix/install/SNYPR/JAVA
	mkdir /Securonix/install/SNYPR/CM
	mkdir /Securonix/install/SNYPR/CDH
	chown -R securonix:securonix /Securonix
	sleep 1

	echo "Installing packages.."
	yum remove mysql-libs -y
	yum -y install perl*
	yum -y install perl-Data-Dumper.x86_64
	yum -y install libaio*
	yum -y install createrepo
	yum -y install yum-utils
	yum -y install MySQL-python*
	yum -y install python*
	yum -y install httpd
	yum -y install telnet
	yum -y install bind*
	yum -y install rpmdevtools
	yum -y install ntp*
	yum -y install redhat-lsb*
	yum -y install cyrus*
	yum -y install mod_ssl*
	yum -y install portmap*
	yum -y install mlocate*
	yum -y remove snappy
	yum -y install dos2unix
	yum -y install gcc
	yum -y install *openldap* migrationtools
	yum -y install openldap-clients nss-pam-ldapd
	yum -y install sssd*
	yum update db
	sleep 1
	
	echo "Enable and start ntpd and ntpdate"
	systemctl enable ntpd
	systemctl enable ntpdate
	systemctl start ntpd
	systemctl start ntpdate
	sleep 1
	
	echo "Disable centos ntp pool"
	sed -i 's/^server /#server /g' /etc/ntp.conf
	sleep 1
	
	echo "Enable and start httpd"
	systemctl enable httpd
	systemctl start httpd
	sleep 1

	echo "Editing and restarting nscd"
	unlimited=$(cat /etc/nscd.conf | grep reload-count | tail -1 | cut -d'n' -f3 | sed -r '/^\s*$/d')
	if [ -z "$unlimited" ]
	then
		echo "        reload-count            unlimited
        positive-time-to-live   passwd          3600
		suggested-size          passwd          211" >> /etc/nscd.conf
	service nscd restart
	else
      echo "nscd already set!!"
	fi
	sleep 1
	

	sleep 1
	
	echo "Editing /etc/security/limits.conf"
	limitstat=$(cat /etc/security/limits.conf | grep "102400" | grep "nproc" | grep "hard")
	if [ -z "$limitstat" ]
	then
		echo "*                soft    nofile          102400
*                hard    nofile          102400
*                soft    nproc           102400
*                hard    nproc           102400" >> /etc/security/limits.conf
	else
		echo "limit already set!"
		sleep 1
	fi
	
	echo "Editing /etc/security/limits.d/20-nproc.conf"
	nprocstat=$(cat /etc/security/limits.d/20-nproc.conf | grep "102400" | grep "nproc" | grep "hard")
	if [ -z "$nprocstat" ]
	then
		echo "*          soft    nofile    102400
*          hard    nofile    102400
*          soft    nproc     102400
*          hard    nproc     102400
root       soft    nproc     unlimited" >> /etc/security/limits.d/20-nproc.conf
	else
		echo "nproc already set!"
		sleep 1
	fi
	
	echo "Checking other setting for limits.conf and 20-nproc.conf"
	hdfsnproc=$(cat /etc/security/limits.conf | grep "hdfs" | grep "nproc")
	if [ -z "$hdfsnproc" ]
	then
		echo hdfs - nofile 32768 >> /etc/security/limits.conf
		echo mapred - nofile 32768 >> /etc/security/limits.conf
		echo hbase - nofile 32768 >> /etc/security/limits.conf
		echo yarn - nofile 32768 >> /etc/security/limits.conf
		echo solr - nofile 32768 >> /etc/security/limits.conf
		echo sqoop2 - nofile 32768 >> /etc/security/limits.conf
		echo spark - nofile 32768 >> /etc/security/limits.conf
		echo hive - nofile 32768 >> /etc/security/limits.conf
		echo impala - nofile 32768 >> /etc/security/limits.conf
		echo hue - nofile 32768 >> /etc/security/limits.conf
		echo kafka - nofile 32768 >> /etc/security/limits.conf
		echo hdfs - nproc 32768 >> /etc/security/limits.conf
		echo mapred - nproc 32768 >> /etc/security/limits.conf
		echo hbase - nproc 32768 >> /etc/security/limits.conf
		echo yarn - nproc 32768 >> /etc/security/limits.conf
		echo solr - nproc 32768 >> /etc/security/limits.conf
		echo sqoop2 - nproc 32768 >> /etc/security/limits.conf
		echo spark - nproc 32768 >> /etc/security/limits.conf
		echo hive - nproc 32768 >> /etc/security/limits.conf
		echo impala - nproc 32768 >> /etc/security/limits.conf
		echo hue - nproc 32768 >> /etc/security/limits.conf
		echo kafka - nproc 32768 >> /etc/security/limits.conf
	else
		echo "hdfsnproc already configured!"
	fi
	
	hdfs20nproc=$(cat /etc/security/limits.d/20-nproc.conf | grep "hdfs" | grep "nproc")
	if [ -z "$hdfs20nproc" ]
	then
		echo hdfs - nproc 32768 >> /etc/security/limits.d/20-nproc.conf
		echo mapred - nproc 32768 >> /etc/security/limits.d/20-nproc.conf
		echo hbase - nproc 32768 >> /etc/security/limits.d/20-nproc.conf
		echo yarn - nproc 32768 >> /etc/security/limits.d/20-nproc.conf
		echo solr - nproc 32768 >> /etc/security/limits.d/20-nproc.conf
		echo sqoop2 - nproc 32768 >> /etc/security/limits.d/20-nproc.conf
		echo spark - nproc 32768 >> /etc/security/limits.d/20-nproc.conf
		echo hive - nproc 32768 >> /etc/security/limits.d/20-nproc.conf
		echo impala - nproc 32768 >> /etc/security/limits.d/20-nproc.conf
		echo hue - nproc 32768 >> /etc/security/limits.d/20-nproc.conf
		echo kafka - nproc 32768 >> /etc/security/limits.d/20-nproc.conf
	else
		echo "hdfs20nproc already configured!"
	fi

	#checking defrag status
	defragstat=$(cat /sys/kernel/mm/transparent_hugepage/defrag | cut -d' ' -f3 | cut -d'[' -f2 | cut -d']' -f1)
	if [[ $defragstat == "never" ]];
	then
		echo "No action required!"
	else
		echo never > /sys/kernel/mm/transparent_hugepage/defrag
	fi
	
	#checking hugepage status
	hugepagestat=$(cat /sys/kernel/mm/transparent_hugepage/enabled | cut -d' ' -f3 | cut -d'[' -f2 | cut -d']' -f1)
	if [[ $hugepagestat == "never" ]];
	then
		echo "No action required for hugepage!"
	else
		echo never > /sys/kernel/mm/transparent_hugepage/enabled
	fi

	#checking rc.local status
	rclocal=$(cat /etc/rc.local | grep "defrag")
	if [ -z "$rclocal" ]
	then
		echo "if test -f /sys/kernel/mm/transparent_hugepage/enabled; 
then
echo never > /sys/kernel/mm/transparent_hugepage/enabled
fi
if test -f /sys/kernel/mm/transparent_hugepage/defrag; 
then
echo never > /sys/kernel/mm/transparent_hugepage/defrag
fi" >> /etc/rc.local
	chmod +x /etc/rc.d/rc.local
	sleep 1
	fi

	echo "Removing openjdk"
	yum remove -y java-1.6.0-openjdk
	yum remove -y java-1.7.0-openjdk
	sleep 1

	echo "Installing JAVA"
	mkdir -p /usr/java
	mkdir -p /usr/share/java
	cd /Securonix/install/SNYPR/JAVA/
	javainstaller=$(ls /Securonix/install/SNYPR/JAVA/ | grep jdk-8u261-linux-x64.rpm )
	if [ -z "$javainstaller" ]
	then
		wget http://centosrepo.spectrum-edge.com/installer/JAVA/jdk-8u261-linux-x64.rpm
		rpm -ivh jdk-8u261-linux-x64.rpm
		#check if java installed successfuly
		javainstall=$(ls /usr/java/jdk1.8.0_261-amd64/ | grep "COPYRIGHT")
		if [[ $javainstall == "COPYRIGHT" ]];
		then
			ln -s /usr/java/jdk* /usr/java/latest && ln -s /usr/java/latest /usr/java/default
		else
			echo "JAVA installation failed"
			exit 1
		fi		
	else
		rpm -ivh jdk-8u261-linux-x64.rpm
		#check if java installed successfuly
		javainstall2=$(ls /usr/java/jdk1.8.0_261-amd64/ | grep "COPYRIGHT")
		if [[ $javainstall2 == "COPYRIGHT" ]];
		then
			ln -s /usr/java/jdk* /usr/java/latest && ln -s /usr/java/latest /usr/java/default
		else
			echo "JAVA installation failed"
			exit 1
		fi
	fi
	sleep 1

	echo "Installing MYSQL Connector"
	cd /Securonix/install/SNYPR/MYSQL
	wget http://centosrepo.spectrum-edge.com/installer/MYSQL/mysql-connector-java-5.1.49.tar.gz
	tar -zxvf mysql-connector-java-5.1.49.tar.gz

	cd /usr/java
	cp /Securonix/install/SNYPR/MYSQL/mysql-connector-java-5.1.49/mysql-connector-java-5.1.49-bin.jar .
	ln -s mysql-connector-java-5.1.49-bin.jar mysql-connector-java.jar
	cp mysql-connector-java-5.1.49-bin.jar /usr/share/java
	cd /usr/share/java
	ln -s mysql-connector-java-5.1.49-bin.jar mysql-connector-java.jar
	
	#disable localrepo
	#yum-config-manager --disable localrepo
	
	echo "Configuration for Master node ONLY!"
	hostname
	read -p "Configure host as Master node? (y/n)?" CONT
	if [ "$CONT" = "y" ]; then
		yum remove mysql-libs -y
	else
        echo "You choose this host as slave node. Configuration will stop here. Thank you!"
		exit 1        
	fi
	sleep 1

	echo "Downloading MYSQL installer version 5.6.35.."
	cd /Securonix/install/SNYPR/MYSQL
	
	mysqlsvrrpm=$(ls /Securonix/install/SNYPR/MYSQL/ | grep MySQL-server-5.6.35-1.el7.x86_64.rpm)
	if [ -z "$mysqlsvrrpm" ]
	then
		wget http://centosrepo.spectrum-edge.com/installer/MYSQL/MySQL-server-5.6.35-1.el7.x86_64.rpm
	else
		echo "MySQL-server-5.6.35-1.el7.x86_64.rpm downloaded"
		sleep 1
	fi
	
	mysqlclirpm=$(ls /Securonix/install/SNYPR/MYSQL/ | grep MySQL-client-5.6.35-1.el7.x86_64.rpm)
	if [ -z "$mysqlclirpm" ]
	then
		wget http://centosrepo.spectrum-edge.com/installer/MYSQL/MySQL-client-5.6.35-1.el7.x86_64.rpm
	else
		echo "MySQL-client-5.6.35-1.el7.x86_64.rpm downloaded"
		sleep 1
	fi
	
	mysqlsharedrpm=$(ls /Securonix/install/SNYPR/MYSQL/ | grep MySQL-shared-5.6.35-1.el7.x86_64.rpm)
	if [ -z "$mysqlsharedrpm" ]
	then
		wget http://centosrepo.spectrum-edge.com/installer/MYSQL/MySQL-shared-5.6.35-1.el7.x86_64.rpm
	else
		echo "MySQL-shared-5.6.35-1.el7.x86_64.rpm downloaded"
		sleep 1
	fi

	mysqlsharedcompatrpm=$(ls /Securonix/install/SNYPR/MYSQL/ | grep MySQL-shared-compat-5.6.35-1.el7.x86_64.rpm)
	if [ -z "$mysqlsharedcompatrpm" ]
	then
		wget http://centosrepo.spectrum-edge.com/installer/MYSQL/MySQL-shared-compat-5.6.35-1.el7.x86_64.rpm
	else
		echo "MySQL-shared-compat-5.6.35-1.el7.x86_64.rpm downloaded"
		sleep 1
	fi
	
	echo "Installing MYSQL from RPM files.."
	rpm -Uhv MySQL-server-5.6.35-1.el7.x86_64.rpm
	rpm -Uhv MySQL-client-5.6.35-1.el7.x86_64.rpm
	rpm -Uhv MySQL-shared-5.6.35-1.el7.x86_64.rpm
	rpm -Uhv MySQL-shared-compat-5.6.35-1.el7.x86_64.rpm
	sleep 1
	
	echo "Starting MYSQL service.."
	service mysql start
	sleep 1
	
	echo "Backuping my.cnf.."
	cp /usr/my.cnf /usr/my.cnf.back
	sleep 1
	
	echo "Restarting MYSQL service.."
	service mysql restart

	echo "Configuraton below will be auto configured.."
	echo "Allow remote login"
	echo "Disable anonymous Login"

	# get Temporary root Password
	root_temp_pass=$(cat /root/.mysql_secret | cut -d':' -f4 | sed '$d' | sed 's/^ *//g')

	echo "root_temp_pass:"$root_temp_pass
	sleep 1
	
	printf '%s\n' ''$root_temp_pass'' 'y' ''$root_temp_pass'' ''$root_temp_pass'' 'y' 'n' 'n' 'y'| 
		sudo script -q -c '/usr/bin/mysql_secure_installation' /dev/null
	sleep 1
	
	mysql -uroot -p$root_temp_pass <<MYSQL_SCRIPT
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' IDENTIFIED BY '$root_temp_pass' WITH GRANT OPTION;
FLUSH PRIVILEGES;
MYSQL_SCRIPT
	sleep 1
	
	echo "Installing Cloudera Cloud Manager.."
	
	cd /Securonix/install/SNYPR/CM/
	wget http://centosrepo.spectrum-edge.com/cm5/redhat/7/x86_64/cm/5.16.2/RPMS/x86_64/cloudera-manager-daemons-5.16.2-1.cm5162.p0.7.el7.x86_64.rpm
	wget http://centosrepo.spectrum-edge.com/cm5/redhat/7/x86_64/cm/5.16.2/RPMS/x86_64/cloudera-manager-server-5.16.2-1.cm5162.p0.7.el7.x86_64.rpm
	wget http://centosrepo.spectrum-edge.com/cm5/redhat/7/x86_64/cm/5.16.2/RPMS/x86_64/cloudera-manager-server-db-2-5.16.2-1.cm5162.p0.7.el7.x86_64.rpm

	yum --nogpgcheck -y localinstall cloudera-manager-daemons-*.rpm
	yum --nogpgcheck -y localinstall cloudera-manager-server-*.rpm

	echo "Prepare the Cloudera Manager database..allow all IP"
	
	# get Temporary root Password
	root_temp_pass2=$(cat /root/.mysql_secret | cut -d':' -f4 | sed '$d' | sed 's/^ *//g')

	mysql -uroot -p$root_temp_pass2 <<CMSCRIPT
create database amon DEFAULT CHARACTER SET utf8;
grant all on amon.* to 'amon'@'%' identified by '$ecurity.4BD';
create database scm DEFAULT CHARACTER SET utf8;
grant all on scm.* to 'scm'@'%' identified by '$ecurity.4BD';
create database rman DEFAULT CHARACTER SET utf8;
grant all on rman.* to 'rman'@'%' identified by '$ecurity.4BD';
create database metastore DEFAULT CHARACTER SET utf8;
grant all on metastore.* to 'hive'@'%' identified by '$ecurity.4BD';
create database sentry DEFAULT CHARACTER SET utf8;
grant all on sentry.* to 'sentry'@'%' identified by '$ecurity.4BD';
create database nav DEFAULT CHARACTER SET utf8;
grant all on nav.* to 'nav'@'%' identified by '$ecurity.4BD';
create database navms DEFAULT CHARACTER SET utf8;
grant all on navms.* to 'navms'@'%' identified by '$ecurity.4BD';
create database hue DEFAULT CHARACTER SET utf8;
grant all on hue.* to 'hue'@'%' identified by '$ecurity.4BD';
create database oozie DEFAULT CHARACTER SET utf8;
grant all on oozie.* to 'oozie'@'%' identified by '$ecurity.4BD';
create database hive DEFAULT CHARACTER SET utf8;
grant all on hive.* to 'hive'@'%' identified by '$ecurity.4BD';
flush privileges;
CMSCRIPT
	sleep 1

	echo "Prepare the Cloudera Manager database..allow all from LOCALHOST"
	
	# get Temporary root Password
	root_temp_pass3=$(cat /root/.mysql_secret | cut -d':' -f4 | sed '$d' | sed 's/^ *//g')

	mysql -uroot -p$root_temp_pass3 <<CMSCRIPTLOCAL
grant all on amon.* to 'amon'@'localhost' identified by '$ecurity.4BD';
grant all on scm.* to 'scm'@'localhost' identified by '$ecurity.4BD';
grant all on rman.* to 'rman'@'localhost' identified by '$ecurity.4BD';
grant all on metastore.* to 'hive'@'localhost' identified by '$ecurity.4BD';
grant all on sentry.* to 'sentry'@'localhost' identified by '$ecurity.4BD';
grant all on nav.* to 'nav'@'localhost' identified by '$ecurity.4BD';
grant all on navms.* to 'navms'@'localhost' identified by '$ecurity.4BD';
grant all on hue.* to 'hue'@'localhost' identified by '$ecurity.4BD';
grant all on oozie.* to 'oozie'@'localhost' identified by '$ecurity.4BD';
grant all on hive.* to 'hive'@'localhost' identified by '$ecurity.4BD';
flush privileges;
CMSCRIPTLOCAL
	sleep 1

	echo "Create the database schema for the cloudera manager.."
	
	mysqlSCMPassword=$ecurity.4BD
	printf '%s\n' ''$mysqlSCMPassword''| 
		sudo script -q -c '/usr/share/cmf/schema/scm_prepare_database.sh mysql scm scm' /dev/null
	sleep 10
		
	echo "Start the Cloudera Manager Server.."
	service cloudera-scm-server start
	
	echo "Waiting for service to start.."
	until $(curl --output /dev/null --silent --head --fail http://localhost:7180); do
	echo -ne '.'
	sleep 10
	done
	echo "Service started!"
	
	myip=$(ifconfig | grep "inet" | head -1 | cut -d' ' -f10)
	echo "Login to Cloudera Manager using IP: http://"$myip":7180/"
	echo "USERID: admin"
	echo "Password: admin"
fi
exit 1
