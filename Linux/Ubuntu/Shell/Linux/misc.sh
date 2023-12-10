#!/bin/bash
echo "-----------------------"
echo "Task 1: Find rootkits, backdoors, etc."
echo "-----------------------"

sudo apt-get install chkrootkit rkhunter
sudo chkrootkit
sudo rkhunter --update
sudo rkhunter --check

unalias -a 
 
echo "open another terminal to kill anything and then proceed by pressing enter" 
read answer
clear

unalias -a #Get rid of aliases
echo "unalias -a" >> ~/.bashrc
echo "unalias -a" >> /root/.bashrc
PWDthi=$(pwd)
if [ ! -d $PWDthi/referenceFiles ]; then
	echo "Please cd into this script's directory"
	exit
fi
if [ "$EUID" -ne 0 ] ;
	then echo "Run as Root"
	exit
fi

startFun()
{
	clear

	PasswdFun
	zeroUidFun
	rootCronFun
	apacheSecFun
	fileSecFun
	netSecFun
	aptUpFun
	aptInstFun
	deleteFileFun
	firewallFun
	sysCtlFun
	scanFun
	printf "\033[1;31mDone!\033[0m\n"
}
cont(){
	printf "\033[1;31mI have finished this task. Continue to next Task? (Y/N)\033[0m\n"
	read contyn
	if [ "$contyn" = "N" ] || [ "$contyn" = "n" ]; then
		printf "\033[1;31mAborted\033[0m\n"
		exit
	fi
	clear
}
PasswdFun(){
	printf "\033[1;31mChanging Root's Password..\033[0m\n"
	#--------- Change Root Password ----------------
	passwd
	echo "Please change other user's passwords too"
	cont
}
zeroUidFun(){
	printf "\033[1;31mChecking for 0 UID users...\033[0m\n"
	#--------- Check and Change UID's of 0 not Owned by Root ----------------
	touch /zerouidusers
	touch /uidusers

	cut -d: -f1,3 /etc/passwd | egrep ':0$' | cut -d: -f1 | grep -v root > /zerouidusers

	if [ -s /zerouidusers ]
	then
		echo "There are Zero UID Users! I'm fixing it now!"

		while IFS='' read -r line || [[ -n "$line" ]]; do
			thing=1
			while true; do
				rand=$(( ( RANDOM % 999 ) + 1000))
				cut -d: -f1,3 /etc/passwd | egrep ":$rand$" | cut -d: -f1 > /uidusers
				if [ -s /uidusers ]
				then
					echo "Couldn't find unused UID. Trying Again... "
				else
					break
				fi
			done
			usermod -u $rand -g $rand -o $line
			touch /tmp/oldstring
			old=$(grep "$line" /etc/passwd)
			echo $old > /tmp/oldstring
			sed -i "s~0:0~$rand:$rand~" /tmp/oldstring
			new=$(cat /tmp/oldstring)
			sed -i "s~$old~$new~" /etc/passwd
			echo "ZeroUID User: $line"
			echo "Assigned UID: $rand"
		done < "/zerouidusers"
		update-passwd
		cut -d: -f1,3 /etc/passwd | egrep ':0$' | cut -d: -f1 | grep -v root > /zerouidusers

		if [ -s /zerouidusers ]
		then
			echo "WARNING: UID CHANGE UNSUCCESSFUL!"
		else
			echo "Successfully Changed Zero UIDs!"
		fi
	else
		echo "No Zero UID Users"
	fi
	cont
}
rootCronFun(){
	printf "\033[1;31mChanging cron to only allow root access...\033[0m\n"
	
	#--------- Allow Only Root Cron ----------------
	#reset crontab
	crontab -r
	cd /etc/
	/bin/rm -f cron.deny at.deny
	echo root >cron.allow
	echo root >at.allow
	/bin/chown root:root cron.allow at.allow
	/bin/chmod 644 cron.allow at.allow
	cont
}
apacheSecFun(){
	printf "\033[1;31mSecuring Apache...\033[0m\n"
	#--------- Securing Apache ----------------
	a2enmod userdir

	chown -R root:root /etc/apache2
	chown -R root:root /etc/apache

	if [ -e /etc/apache2/apache2.conf ]; then
		echo "<Directory />" >> /etc/apache2/apache2.conf
		echo "        AllowOverride None" >> /etc/apache2/apache2.conf
		echo "        Order Deny,Allow" >> /etc/apache2/apache2.conf
		echo "        Deny from all" >> /etc/apache2/apache2.conf
		echo "</Directory>" >> /etc/apache2/apache2.conf
		echo "UserDir disabled root" >> /etc/apache2/apache2.conf
	fi

	systemctl restart apache2.service
	cont
}
fileSecFun(){
	printf "\033[1;31mSome automatic file inspection...\033[0m\n"
	#--------- Manual File Inspection ----------------
	cut -d: -f1,3 /etc/passwd | egrep ':[0-9]{4}$' | cut -d: -f1 > /tmp/listofusers
	echo root >> /tmp/listofusers
	
	#Replace sources.list with safe reference file (For Ubuntu 14 Only)
	cat $PWDthi/referenceFiles/sources.list > /etc/apt/sources.list
	apt-get update

	#Replace lightdm.conf with safe reference file
	cat $PWDthi/referenceFiles/lightdm.conf > /etc/lightdm/lightdm.conf

	#Replace sshd_config with safe reference file
	cat $PWDthi/referenceFiles/sshd_config > /etc/ssh/sshd_config
	/usr/sbin/sshd -t
	systemctl restart sshd.service

	#/etc/rc.local should be empty except for 'exit 0'
	echo 'exit 0' > /etc/rc.local

	printf "\033[1;31mFinished automatic file inspection. Continue to manual file inspection? (Y/N)\033[0m\n"
	read contyn
	if [ "$contyn" = "N" ] || [ "$contyn" = "n" ]; then
		exit
	fi
	clear

	printf "\033[1;31mSome manual file inspection...\033[0m\n"

	#Manual File Inspection
	nano /etc/resolv.conf #make sure if safe, use 8.8.8.8 for name server
	nano /etc/hosts #make sure is not redirecting
	visudo #make sure sudoers file is clean. There should be no "NOPASSWD"
	nano /tmp/listofusers #No unauthorized users

	cont
}
netSecFun(){ 
	printf "\033[1;31mSome manual network inspection...\033[0m\n"
	#--------- Manual Network Inspection ----------------
	lsof -i -n -P
	netstat -tulpn
	cont
}
aptUpFun(){
	printf "\033[1;31mUpdating computer...\033[0m\n"
	#--------- Update Using Apt-Get ----------------
	#apt-get update --no-allow-insecure-repositories
	apt-get update
	apt-get dist-upgrade -y
	apt-get install -f -y
	apt-get autoremove -y
	apt-get autoclean -y
	apt-get check
	cont
}
aptInstFun(){
	printf "\033[1;31mInstalling programs...\033[0m\n"
	#--------- Download programs ----------------
	apt-get install -y chkrootkit clamav rkhunter apparmor apparmor-profiles

	#This will download lynis 2.4.0, which may be out of date
	wget https://cisofy.com/files/lynis-2.5.5.tar.gz -O /lynis.tar.gz
	tar -xzf /lynis.tar.gz --directory /usr/share/
	cont
}
deleteFileFun(){
	printf "\033[1;31mDeleting dangerous files...\033[0m\n"
	#--------- Delete Dangerous Files ----------------
	find / -name '*.mp3' -type f -delete
	find / -name '*.mov' -type f -delete
	find / -name '*.mp4' -type f -delete
	find / -name '*.avi' -type f -delete
	find / -name '*.mpg' -type f -delete
	find / -name '*.mpeg' -type f -delete
	find / -name '*.flac' -type f -delete
	find / -name '*.m4a' -type f -delete
	find / -name '*.flv' -type f -delete
	find / -name '*.ogg' -type f -delete
	find /home -name '*.gif' -type f -delete
	find /home -name '*.png' -type f -delete
	find /home -name '*.jpg' -type f -delete
	find /home -name '*.jpeg' -type f -delete
	cd / && ls -laR 2> /dev/null | grep rwxrwxrwx | grep -v "lrwx" &> /tmp/777s
	cont

	printf "\033[1;31m777 (Full Permission) Files : \033[0m\n"
	printf "\033[1;31mConsider changing the permissions of these files\033[0m\n"
	cat /tmp/777s
	cont
}
firewallFun(){
	printf "\033[1;31mSetting up firewall...\033[0m\n"
	#--------- Setup Firewall ----------------
	#Please verify that the firewall wont block any services, such as an Email server, when defaulted.
	#I will back up iptables for you in and put it in /iptables/rules.v4.bak and /iptables/rules.v6.bak
	#Uninstall UFW and install iptables
	apt-get remove -y ufw
	apt-get install -y iptables
	apt-get install -y iptables-persistent
	#Backup
	mkdir /iptables/
	touch /iptables/rules.v4.bak
	touch /iptables/rules.v6.bak
	iptables-save > /iptables/rules.v4.bak
	ip6tables-save > /iptables/rules.v6.bak
	#Clear out and default iptables
	iptables -t nat -F
	iptables -t mangle -F
	iptables -t nat -X
	iptables -t mangle -X
	iptables -F
	iptables -X
	iptables -P INPUT DROP
	iptables -P FORWARD DROP
	iptables -P OUTPUT ACCEPT
	ip6tables -t nat -F
	ip6tables -t mangle -F
	ip6tables -t nat -X
	ip6tables -t mangle -X
	ip6tables -F
	ip6tables -X
	ip6tables -P INPUT DROP
	ip6tables -P FORWARD DROP
	ip6tables -P OUTPUT DROP
	#Block Bogons
	printf "\033[1;31mEnter primary internet interface: \033[0m\n"
	read interface
	#Blocks bogons going into the computer
	iptables -A INPUT -s 127.0.0.0/8 -i $interface -j DROP
	iptables -A INPUT -s 0.0.0.0/8 -j DROP
	iptables -A INPUT -s 100.64.0.0/10 -j DROP
	iptables -A INPUT -s 169.254.0.0/16 -j DROP
	iptables -A INPUT -s 192.0.0.0/24 -j DROP
	iptables -A INPUT -s 192.0.2.0/24 -j DROP
	iptables -A INPUT -s 198.18.0.0/15 -j DROP
	iptables -A INPUT -s 198.51.100.0/24 -j DROP
	iptables -A INPUT -s 203.0.113.0/24 -j DROP
	iptables -A INPUT -s 224.0.0.0/3 -j DROP
	#Blocks bogons from leaving the computer
	iptables -A OUTPUT -d 127.0.0.0/8 -o $interface -j DROP
	iptables -A OUTPUT -d 0.0.0.0/8 -j DROP
	iptables -A OUTPUT -d 100.64.0.0/10 -j DROP
	iptables -A OUTPUT -d 169.254.0.0/16 -j DROP
	iptables -A OUTPUT -d 192.0.0.0/24 -j DROP
	iptables -A OUTPUT -d 192.0.2.0/24 -j DROP
	iptables -A OUTPUT -d 198.18.0.0/15 -j DROP
	iptables -A OUTPUT -d 198.51.100.0/24 -j DROP
	iptables -A OUTPUT -d 203.0.113.0/24 -j DROP
	iptables -A OUTPUT -d 224.0.0.0/3 -j DROP
	#Blocks outbound from source bogons - A bit overkill
	iptables -A OUTPUT -s 127.0.0.0/8 -o $interface -j DROP
	iptables -A OUTPUT -s 0.0.0.0/8 -j DROP
	iptables -A OUTPUT -s 100.64.0.0/10 -j DROP
	iptables -A OUTPUT -s 169.254.0.0/16 -j DROP
	iptables -A OUTPUT -s 192.0.0.0/24 -j DROP
	iptables -A OUTPUT -s 192.0.2.0/24 -j DROP
	iptables -A OUTPUT -s 198.18.0.0/15 -j DROP
	iptables -A OUTPUT -s 198.51.100.0/24 -j DROP
	iptables -A OUTPUT -s 203.0.113.0/24 -j DROP
	iptables -A OUTPUT -s 224.0.0.0/3 -j DROP
	#Block receiving bogons intended for bogons - Super overkill
	iptables -A INPUT -d 127.0.0.0/8 -i $interface -j DROP
	iptables -A INPUT -d 0.0.0.0/8 -j DROP
	iptables -A INPUT -d 100.64.0.0/10 -j DROP
	iptables -A INPUT -d 169.254.0.0/16 -j DROP
	iptables -A INPUT -d 192.0.0.0/24 -j DROP
	iptables -A INPUT -d 192.0.2.0/24 -j DROP
	iptables -A INPUT -d 198.18.0.0/15 -j DROP
	iptables -A INPUT -d 198.51.100.0/24 -j DROP
	iptables -A INPUT -d 203.0.113.0/24 -j DROP
	iptables -A INPUT -d 224.0.0.0/3 -j DROP
	iptables -A INPUT -i lo -j ACCEPT
	#Least Strict Rules
	#iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	#Strict Rules -- Only allow well known ports (1-1022)
	#iptables -A INPUT -p tcp --match multiport --sports 1:1022 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	#iptables -A INPUT -p udp --match multiport --sports 1:1022 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	#iptables -A OUTPUT -p tcp --match multiport --dports 1:1022 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	#iptables -A OUTPUT -p udp --match multiport --dports 1:1022 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	#iptables -A OUTPUT -o lo -j ACCEPT
	#iptables -P OUTPUT DROP
	#Very Strict Rules - Only allow HTTP/HTTPS, NTP and DNS
	iptables -A INPUT -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	iptables -A INPUT -p tcp --sport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	iptables -A INPUT -p tcp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	iptables -A INPUT -p udp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -p tcp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -o lo -j ACCEPT
	iptables -P OUTPUT DROP
	mkdir /etc/iptables/
	touch /etc/iptables/rules.v4
	touch /etc/iptables/rules.v6
	iptables-save > /etc/iptables/rules.v4
	ip6tables-save > /etc/iptables/rules.v6
	cont
}
sysCtlFun(){
	printf "\033[1;31mMaking Sysctl Secure...\033[0m\n"
	#--------- Secure /etc/sysctl.conf ----------------
	sysctl -w net.ipv4.tcp_syncookies=1
	sysctl -w net.ipv4.ip_forward=0
	sysctl -w net.ipv4.conf.all.send_redirects=0
	sysctl -w net.ipv4.conf.default.send_redirects=0
	sysctl -w net.ipv4.conf.all.accept_redirects=0
	sysctl -w net.ipv4.conf.default.accept_redirects=0
	sysctl -w net.ipv4.conf.all.secure_redirects=0
	sysctl -w net.ipv4.conf.default.secure_redirects=0
	sysctl -p
	cont
}
scanFun(){
	printf "\033[1;31mScanning for Viruses...\033[0m\n"
	#--------- Scan For Vulnerabilities and viruses ----------------

	#chkrootkit
	printf "\033[1;31mStarting CHKROOTKIT scan...\033[0m\n"
	chkrootkit -q
	cont

	#Rkhunter
	printf "\033[1;31mStarting RKHUNTER scan...\033[0m\n"
	rkhunter --update
	rkhunter --propupd #Run this once at install
	rkhunter -c --enable all --disable none
	cont
	
	#Lynis
	printf "\033[1;31mStarting LYNIS scan...\033[0m\n"
	cd /usr/share/lynis/
	/usr/share/lynis/lynis update info
	/usr/share/lynis/lynis audit system
	cont
	
	#ClamAV
	printf "\033[1;31mStarting CLAMAV scan...\033[0m\n"
	systemctl stop clamav-freshclam
	freshclam --stdout
	systemctl start clamav-freshclam
	clamscan -r -i --stdout --exclude-dir="^/sys" /
	cont
}

repoFun(){
	read -p "Please check the repo for any issues [Press any key to continue...]" -n1 -s
	nano /etc/apt/sources.list
	gpg /etc/apt/trusted.gpg > /tmp/trustedGPG
	printf "\033[1;31mPlease check /tmp/trustedGPG for trusted GPG keys\033[0m\n"
	cont
}

echo "do you want to run fun? (y/n)"
read choice 
if [[ $choice == "Yy" ]]; then
  startFun
elif [[ $choice == "n" ]]; then
echo "not running run"
fi 

else
  # If the user enters an invalid choice, let them know
  echo "Invalid choice."
fi

echo "do you want to edit cracklib (Y/n)"
read choice
if [[ $choice == "Yy" ]]; then
    # Cracklib install
    apt-get install libpam-cracklib
    # Password history of 5 and length of 8:
    sed -i '/pam_unix\.so/s/$/\tremember=5\tminlen=8\tsha512' /etc/pam.d/common-password
    # Passwords must be complicated.
    sed -i '/pam_cracklib\.so/s/$/\tucredit=-1\tlcredit=-1\tdcredit=-1\tocredit=-1/' /etc/pam.d/common-password
fi 

echo "do you want to edit password durations (Y/n)"
read choice
if [[ $choice == "Yy" ]]; then

    # Set password durations.
    sed -i '/^PASS_MAX_DAYS\s*[0-9]+/s/[0-9]+/90/' /etc/login.defs  # Maximum
    sed -i '/^PASS_MIN_DAYS\s*[0-9]+/s/[0-9]+/10/' /etc/login.defs  # Minimum
    sed -i '/^PASS_WARN_AGE\s*[0-9]+/s/[0-9]+/7/' /etc/login.defs  # Days before expiration to warn user.
fi 

echo "do you want to edit lockout policies (Y/n)"
read choice
if [[ $choice == "Yy" ]]; then
# account lockout policies.
# this sets the number of failed login attempts to 5
# and the lockout duration to 1800 seconds (30 minutes).
    printf "auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800\n" >> /etc/pam.d/common-auth
fi 

echo "do you want to setup audits (Y/n)"
read choice
if [[ $choice == "Yy" ]]; then
# setup audits
    apt-get install auditd
    auditctl -e 1
fi 

echo "do you want to setup audits (Y/n)"
read choice
if [[ $choice == "Yy" ]]; then
# install ansible in case we want to run a playbook.
    apt-get update
    apt-get install software-properties-common
    apt-add-repository --yes --update ppa:ansible/ansible
    apt-get install ansible
fi


echo "do you want to set GID 0 as default group for root account (Y/n)"
read choice
if [[ $choice == "Yy" ]]; then

# Set GID 0 as default group for root account
usermod -g 0 root
fi 


echo "do you want to set cron stuff (Y/n)"
read choice
if [[ $choice == "Yy" ]]; then

    systemctl enable cron
    chown root:root /etc/crontab
    chmod og-rwx /etc/crontab
    chown root:root /etc/cron.hourly
    chmod og-rwx /etc/cron.hourly
    chown root:root /etc/cron.daily
    chmod og-rwx /etc/cron.daily
    chown root:root /etc/cron.weekly
    chmod og-rwx /etc/cron.weekly
    chown root:root /etc/cron.monthly
    chmod og-rwx /etc/cron.monthly
    chown root:root /etc/cron.d
    chmod og-rwx /etc/cron.d
    rm /etc/cron.deny
    rm /etc/at.deny
    touch /etc/cron.allow
    touch /etc/at.allow
    chmod /etc/cron.allow
    chmod /etc/at.allow
    chown /etc/cron.allow
    chown /etc/at.allow
fi



# Uninstall openbsd-inetd
apt-get remove openbsd-inetd

# Uninstall X Window System
apt-get remove xserver-xorg\*

# remove clients:
apt-get remove nis
apt-get remove rsh-client rsh-redone-client
apt-get remove talk
apt-get remove telnet
apt-get remove ldap-utils

# Disable prelink
prelink -ua
apt-get remove prelink

systemctl disable autofs
systemctl disable xinetd
systemctl disable avahi-daemon
systemctl disable cups
systemctl disable isc-dhcp-server
systemctl disable isc-dhcp-server6
systemctl disable slapd
systemctl disable nfs-server
systemctl disable rpcbind
systemctl disable bind9
systemctl disable apache2
systemctl disable dovecot
systemctl disable smbd
systemctl disable squid
systemctl disable snmpd
systemctl disable rsync
systemctl disable nis
systemctl enable rsyslog

clear

echo "do you want to set root stuff (Y/n)"
read choice
if [[ $choice == "Yy" ]]; then
    grep root /etc/passwd | wc -l
    echo -e "UID 0 is not correctly set to root. Please fix.\nPress enter to continue..."
    read waiting
fi
echo "UID 0 is correctly set to root."

clear
sed -i '1c\
root:x:0:0:root:/root:/sbin/nologin' /etc/passwd
echo "Root has been set to nologin"

echo "do you want to set Bash history (Y/n)"
read choice
if [[ $choice == "Yy" ]]; then
    clear
    chmod 640 .bash_history
    echo "Bash history file permissions set."

    clear
    chmod 600 /etc/shadow
    echo "File permissions on shadow have been set."

    clear
    chmod 644 /etc/passwd
    echo "File permissions on passwd have been set."

fi 


echo "do you want to set install iptables (Y/n)"
read choice
if [[ $choice == "Yy" ]]; then

    apt-get -y -qq install iptables
    iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 23 -j DROP
    iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 2049 -j DROP
    iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 2049 -j DROP
    iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 6000:6009 -j DROP
    iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 7100 -j DROP
    iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 515 -j DROP
    iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 515 -j DROP
    iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 111 -j DROP
    iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 111 -j DROP
    iptables -A INPUT -p all -s localhost  -i eth0 -j DROP
    echo "IPtables has been installed and telnet, NFS, X-Windows, printer, and Sun rcp/NFS have been blocked. If any of these are needed, use google to find how to unlock."
    iptables -I INPUT -p tcp --dport 22 -i eth0 -m state --state NEW -m recent --set
    iptables -I INPUT -p tcp --dport 22 -i eth0 -m state --state NEW -m recent --update --seconds 60 --hitcount 5 -j DROP
    iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
    iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP
    iptables -A INPUT -m recent --name portscan --remove
    iptables -A FORWARD -m recent --name portscan --remove
    iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
    iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP
    iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
    iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP
    echo "SSH spammers and portscans have been blocked. Blocks removed after 1 day, and scan attempts are logged."
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
    iptables -A OUTPUT -p icmp -o eth0 -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type echo-reply -s 0/0 -i eth0 -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type destination-unreachable -s 0/0 -i eth0 -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type time-exceeded -s 0/0 -i eth0 -j ACCEPT
    iptables -A INPUT -p icmp -i eth0 -j DROP
    echo "NULL packets and pings are dropped."
    iptables-save
    /sbin/iptables-save
    echo "IPtables rules saved."
fi 

echo "do you want to set configurations & other cool stuff (Y/n)"
read choice
if [[ $choice == "Yy" ]]; then
    clear
    chmod 777 /etc/hosts
    cp /etc/hosts ~/Desktop/backups/
    echo > /etc/hosts
    echo -e "127.0.0.1 localhost\n127.0.1.1 $USER\n::1 ip6-localhost ip6-loopback\nfe00::0 ip6-localnet\nff00::0 ip6-mcastprefix\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters" >> /etc/hosts
    chmod 644 /etc/hosts
    echo "HOSTS file has been set to defaults."

    chmod 777 /etc/host.conf
    cp /etc/host.conf ~/Desktop/backups/
    echo > /etc/host.conf
    echo -e "# The \"order\" line is only used by old versions of the C library.\norder hosts,bind\nmulti on" >> /etc/host.conf
    chmod 644 /etc/host.conf
    echo "host.conf has been set to defaults."

    clear
    chmod 777 /etc/lightdm/lightdm.conf
    cp /etc/lightdm/lightdm.conf ~/Desktop/backups/
    echo > /etc/lightdm/lightdm.conf
    echo -e '[SeatDefaults]\nallow-guest=false\ngreeter-hide-users=true\ngreeter-show-manual-login=true' >> /etc/lightdm/lightdm.conf
    chmod 644 /etc/lightdm/lightdm.conf
    echo "LightDM has been secured."

    clear
    cp /etc/default/irqbalance ~/Desktop/backups/
    echo > /etc/default/irqbalance
    echo -e "#Configuration for the irqbalance daemon\n\n#Should irqbalance be enabled?\nENABLED=\"0\"\n#Balance the IRQs only once?\nONESHOT=\"0\"" >> /etc/default/irqbalance
    echo "IRQ Balance has been disabled."

    clear
    cp /etc/sysctl.conf ~/Desktop/backups/
    echo > /etc/sysctl.conf
    echo -e "# Controls IP packet forwarding\nnet.ipv4.ip_forward = 0\n\n# IP Spoofing protection\nnet.ipv4.conf.all.rp_filter = 1\nnet.ipv4.conf.default.rp_filter = 1\n\n# Ignore ICMP broadcast requests\nnet.ipv4.icmp_echo_ignore_broadcasts = 1\n\n# Disable source packet routing\nnet.ipv4.conf.all.accept_source_route = 0\nnet.ipv6.conf.all.accept_source_route = 0\nnet.ipv4.conf.default.accept_source_route = 0\nnet.ipv6.conf.default.accept_source_route = 0\n\n# Ignore send redirects\nnet.ipv4.conf.all.send_redirects = 0\nnet.ipv4.conf.default.send_redirects = 0\n\n# Block SYN attacks\nnet.ipv4.tcp_syncookies = 1\nnet.ipv4.tcp_max_syn_backlog = 2048\nnet.ipv4.tcp_synack_retries = 2\nnet.ipv4.tcp_syn_retries = 5\n\n# Log Martians\nnet.ipv4.conf.all.log_martians = 1\nnet.ipv4.icmp_ignore_bogus_error_responses = 1\n\n# Ignore ICMP redirects\nnet.ipv4.conf.all.accept_redirects = 0\nnet.ipv6.conf.all.accept_redirects = 0\nnet.ipv4.conf.default.accept_redirects = 0\nnet.ipv6.conf.default.accept_redirects = 0\n\n# Ignore Directed pings\nnet.ipv4.icmp_echo_ignore_all = 1\n\n# Accept Redirects? No, this is not router\nnet.ipv4.conf.all.secure_redirects = 0\n\n# Log packets with impossible addresses to kernel log? yes\nnet.ipv4.conf.default.secure_redirects = 0\n\n########## IPv6 networking start ##############\n# Number of Router Solicitations to send until assuming no routers are present.\n# This is host and not router\nnet.ipv6.conf.default.router_solicitations = 0\n\n# Accept Router Preference in RA?\nnet.ipv6.conf.default.accept_ra_rtr_pref = 0\n\n# Learn Prefix Information in Router Advertisement\nnet.ipv6.conf.default.accept_ra_pinfo = 0\n\n# Setting controls whether the system will accept Hop Limit settings from a router advertisement\nnet.ipv6.conf.default.accept_ra_defrtr = 0\n\n#router advertisements can cause the system to assign a global unicast address to an interface\nnet.ipv6.conf.default.autoconf = 0\n\n#how many neighbor solicitations to send out per address?\nnet.ipv6.conf.default.dad_transmits = 0\n\n# How many global unicast IPv6 addresses can be assigned to each interface?
    net.ipv6.conf.default.max_addresses = 1\n\n########## Other ##########\nfs.suid_dumpable = 0\nkernel.exec-shield = 2\nkernel.randomize_va_space = 2\nkernel.sysrq = 0\nnet.ipv4.tcp_rfc1337 = 1\n" >> /etc/sysctl.conf
    sysctl -p >> /dev/null
    echo "Sysctl has been configured."

    clear
    cp /proc/sys/kernel/sysrq ~/Desktop/backups/
    echo 0 > /proc/sys/kernel/sysrq
    echo "SysRq key has been disabled"

    clear
    cp /proc/sys/net/ipv4/tcp_rfc1337 ~/Desktop/backups/
    echo 1 > /proc/sys/net/ipv4/tcp_rfc1337
    echo "Kernel drops RST packets for sockets in the time-wait state."

    clear
    cp /proc/sys/kernel/core_uses_pid ~/Desktop/backups/
    echo 1 > /proc/sys/kernel/core_uses_pid
    echo "Kernel core_uses_pid set to 1."

    clear
    cp /proc/sys/net/ipv4/conf/default/log_martians ~/Desktop/backups/
    echo 1 > /proc/sys/net/ipv4/conf/default/log_martians
    echo "Default log_martians set to 1."

    clear
    cp /proc/sys/net/ipv4/tcp_timestamps ~/Desktop/backups/
    echo 0 > /proc/sys/net/ipv4/tcp_timestamps
    echo "tcp_timestamps set to 0."

    clear
    cp /etc/resolv.conf ~/Desktop/backups/
    echo -e "nameserver 8.8.8.8\nsearch localdomain" >> /etc/resolv.conf
    echo "resolv.conf has been configured."

    clear
    cp /etc/init/control-alt-delete.conf ~/Desktop/backups/
    sed '/^exec/ c\exec false' /etc/init/control-alt-delete.conf
    systemctl mask ctrl-alt-del.target #ubuntu 16 only?
    systemctl daemon-reload #ubuntu 16 only?
    echo "Reboot using Ctrl-Alt-Delete has been disabled."
fi 
echo "Disable IPv6? (yes/)"
read ipv6YN
if [ $ipv6YN == yes ]
then
	echo -e "\n\n# Disable IPv6\nnet.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1\nnet.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
	sysctl -p >> /dev/null
	echo "IPv6 has been disabled."
fi

