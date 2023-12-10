#!/bin/bash

# Save this file to your desktop with the name _LinuxSecurity.sh.
# Make sure the name ends with sh.
#
# Then open a terminal session, change to your Desktop folder and execute it with: sudo sh _LinuxSecurity.bat


# Shell script to do much of the basic CyberPatriot Ubuntu tasks.
# Will run updates, create an HTML page with every user and folder and the amount of memory they each use and a list of default Ubuntu programs, force update Firefox and Libre Office, and set a password policy.
# TODO: Add a list of default Ubuntu 14.04 processes.
# Written for Ubuntu 14.04! No guarantee it will work in earlier or later versions!!
# DO THE FORENSICS QUESTIONS FIRST!!!

##### Constants

TITLE="System Information for $HOSTNAME"
RIGHT_NOW=$(date +"%x %r %Z")
TIME_STAMP="Updated on $RIGHT_NOW by $USER"
if [ false ]; then
if [ true ]; then
	echo If you want to understand gaming from the past, look up the terms XYZZY, "Twisty little maze of passages", and "Twisty maze of little passages".
	echo https://www.amc.com/shows/halt-and-catch-fire/exclusives/colossal-cave-adventure
	exit 4
fi


##### Set by user

##### Functions

show_uptime()
{
	echo "<h2>System uptime</h2>"
	echo "<pre>"
	uptime
	echo "</pre>"
}

drive_space()
{
	echo "<h2>Filesystem space</h2>"
	echo "<pre>"
	df
	echo "</pre>"
}

home_space()
{
	echo "<h2>Home directory space by user</h2>"
	echo "<pre>"
	format="%8s%10s%10s   %-s\n"
	printf "$format" "Dirs" "Files" "Blocks" "Directory"
	printf "$format" "----" "-----" "------" "---------"
	if [ $(id -u) = "0" ]; then
		dir_list="/home/*"
	else
		dir_list=$HOME
	fi
	for home_dir in $dir_list; do
		total_dirs=$(find $home_dir -type d | wc -l)
		total_files=$(find $home_dir -type f | wc -l)
		total_blocks=$(du -s $home_dir)
		printf "$format" $total_dirs $total_files $total_blocks
	done
	echo "</pre>"
}

program_list()
{
	echo "<h2>Default programs on Ubuntu 14.04</h2>"
	echo "<h3>Libre Office and Firefox are allowed always.</h3>"
	echo "<pre>"
	echo "<h3>Accessories</h3>"
	echo "<ul>"
	echo "<li>Disks</li>"
	echo "<li>Time & Date</li>"
	echo "<li>Activities and Privacy Manager Tool</li>"
	echo "<li>Text Editor</li>"
	echo "<li>Terminal</li>"
	echo "<li>Font Viewer<li>"
	echo "<li>XTerm</li>"
	echo "<li>Archive Manager</li>"
	echo "<li>Bluetooth Transfer</li>"
	echo "<li>Calculator</li>"
	echo "<li>Deja Dup Backup Tool</li>"
	echo "<li>Character Map</li>"
	echo "<li>Contacts</li>"
	echo "<li>Help</li>"
	echo "</ul>"
	echo "<h3>Developer Tools</h3>"
	echo "<ul>"
	echo "<li>Python (v3.4) (I'M NOT CERTAIN ON THIS ONE)</li>"
	echo "<li>Printers</li>"
	echo "<li>xdiagnose</li>"
	echo "</ul>"
	echo "<h3>Graphics</h3>"
	echo "<ul>"
	echo "<li>Image Viewer (eog)</li>"
	echo "<li>Shotwell Photo Manager</li>"
	echo "<li>Print Preview</li>"
	echo "<li>Document Viewer</li>"
	echo "<li>Simple Scan</li>"
	echo "<li>Shotwell Photo Viewer</li>"
	echo "<li>Photo lens for Unity</li>"
	echo "</ul>"
	echo "<h3>Internet</h3>"
	echo "<ul>"
	echo "<li>Ubufox extension for Firefox</li>"
	echo "<li>Desktop Sharing</li>"
	echo "<li>Browser</li>"
	echo "<li>Empathy Internet Messaging</li>"
	echo "<li>Thunderbird Mail</li>"
	echo "<li>Remmina Remote Desktop Client</li>"
	echo "<li>Transmission BitTorrent Client (SHOULD PROBABLY DELETE THIS ANYWAY)</li>"
	echo "</ul>"
	echo "<h3>Office</h3>"
	echo "<ul><li>Google Drive scope for Unity</li></ul>"
	echo "<h3>Sound & Video</h3>"
	echo "<ul>"
	echo "<li>Cheese Webcam Booth</li>"
	echo "<li>Videos</li>"
	echo "<li>Brasero Disc Burner</li>"
	echo "<li>Rythmbox Music Player</li>"
	echo "</ul>"
	echo "<h3>Themes & Tweaks</h3>"
	echo "<ul>"
	echo "<li>Software & Updates</li>"
	echo "<li>Personal File Sharing</li>"
	echo "<li>Universal Access</li>"
	echo "<li>Power</li>"
	echo "<li>Bluetooth Device Setup</li>"
	echo "<li>Network</li>"
	echo "<li>Color</li>"
	echo "<li>Online Accounts</li>"
	echo "<li>Landscape Service</li>"
	echo "<li>User Accounts</li>"
	echo "<li>Passwords and Keys</li>"
	echo "<li>Software Updater</li>"
	echo "<li>Displays</li>"
	echo "<li>Input Method</li>"
	echo "<li>Bluetooth</li>"
	echo "<li>Brightness & Lock</li>"
	echo "<li>Details</li>"
	echo "<li>Startup Disk Creator</li>"
	echo "<li>Mouse & Touchpad</li>"
	echo "<li>Keyboard Input Methods</li>"
	echo "<li>Language Support</li>"
	echo "<li>Sound</li>"
	echo "<li>Text Entry</li>"
	echo "<li>Software & Updates</li>"
	echo "<li>Wacom Tablet</li>"
	echo "<li>Ubuntu Software Center</li>"
	echo "<li>Keyboard</li>"
	echo "<li>Appearance</li>"
	echo "<li>Online Accounts</li>"
	echo "</ul>"
	echo "<h3>Universal Access</h3>"
	echo "<ul>"
	echo "<li>Orca Screen Reader</li>"
	echo "<li>Onboard</li>"
	echo "</ul>"
	echo "<h3>Uncategorized (NEED TO DOUBLE CHECK)</h3>"
	echo "<ul>"
	echo "<li>GNOME System Monitor</li>"
	echo "<li>Unity Webapps QML Test Launcher</li>"
	echo "<li>IBus Pinyin Setup</li>"
	echo "<li>Keyboard Layout</li>"
	echo "<li>Evolution Data Server</li>"
	echo "<li>View File</li>"
	echo "<li>Power Statistics</li>"
	echo "<li>Account authorization</li>"
	echo "<li>Network</li>"
	echo "<li>Disk Image Mounter</li>"
	echo "<li>Reactivate HP Laser Jet...</li>"
	echo "<li>Disk Image Writer</li>"
	echo "<li>Access Prompt</li>"
	echo "<li>System Testing</li>"
	echo "<li>System Settings</li>"
	echo "<li>Compiz</li>"
	echo "<li>IBus Bopomofo Preferences</li>"
	echo "<li>Account update tool</li>"
	echo "<li>AptURL</li>"
	echo "</ul>"
	echo "<h3>There are also about 1728 technical items.</h3"
	echo "</pre>"
}

process_list()
{
	echo "<h2>Running Services</h2>"
	echo "<pre>"
		service --status-all | less -P "le Services"
	echo "</pre>"
}

user_groups()
{
	echo "<h2>Users in Special Groups</h2>"
	echo "<pre>"
	echo "Members of group 'adm':"
    grep adm /etc/group | cut -d ':' -f 4
    echo "Members of group 'root':"
    grep root /etc/group | cut -d ':' -f 4
    echo "Members of group 'sudo':"
    grep sudo /etc/group | cut -d ':' -f 4
	echo "</pre>"
}

find_media()
{
	echo "<h2>Media Files</h2>"
	echo "<pre>"
	find /home/ | egrep -e ".*.(jpg|tif|png|gif|wav|mp3|ogg|flac|wma|aac|m4a|flv|webm|ogv|gif|gifv|avi|wmv|mp4|mpg|3gp)"
	echo "</pre>"
}

write_page()
{
	cat <<- _EOF_
	<html>
		<head>
		<title>$TITLE</title>
		</head>

		<body>
		<h1>$TITLE</h1>
		<p>$TIME_STAMP</p>
		$(show_uptime)
		$(drive_space)
		$(home_space)
		$(user_groups)
		$(find_media)
		$(program_list)
		$(process_list)
		</body>
	</html>
_EOF_
}

set_users()
{
	for i in `more userlist.txt `
		do
		echo $i
		adduser $i
	done
}

set_passwords()
{
	for i in `more userlist.txt `
	do
		echo $i
		echo "+AcVd8$#C7yhnP=!uLY%" | passwd Š-stdin "$i"
		echo; echo "User $usernameÕs password changed!"
	done
}

set_update_settings()
{
    # these are the recommended settings set in software-properties-gtk
    apt_config=/etc/apt/apt.conf.d/10periodic
    echo "APT::Periodic::Update-Package-Lists \"1\";" > $apt_config
    echo "APT::Periodic::Download-Upgradeable-Packages \"1\";" >> $apt_config
    echo "APT::Periodic::AutocleanInterval \"0\";" >> $apt_config
    echo "APT::Periodic::Unattended-Upgrade \"1\";" >> $apt_config
    echo "Set apt update settings"
}

disable_ssh_root_login()
{
    if [[ -f /etc/ssh/sshd_config ]]; then
        sed -i 's/PermitRootLogin .*/PermitRootLogin no/g' /etc/ssh/sshd_config
    else
        echo "No SSH server detected so nothing changed"
    fi
    echo "Disabled SSH root login"
}

preserve_root_uid()
{
    if [[ $(grep root /etc/passwd | wc -l) -gt 1 ]]; then
        grep root /etc/passwd | wc -l
    else
        echo "$(tput setaf 2)UID 0 is reserved to root$(tput sgr0)"
    fi
}

remove_hacking_tools()
{
    echo "$(tput setaf 2)Basically removing every program in Kali$(tput sgr0)"
    apt-get autoremove --purge --force-yes -y airbase-ng acccheck ace-voip amap apache-users arachni android-sdk apktool arduino armitage asleap automater \
	backdoor-factory bbqsql bed beef bing-ip2hosts binwalk blindelephant bluelog bluemaho bluepot blueranger bluesnarfer bulk-extractor \
	bully burpsuite braa \
	capstone casefile cdpsnarf cewl chntpw cisco-auditing-tool cisco-global-exploiter cisco-ocs cisco-torch cisco-router-config cmospwd \
	cookie-cadger commix cowpatty crackle creddump crunch cryptcat cymothoa copy-router-config cuckoo cutycapt \
	davtest dbd dbpwaudit dc3dd ddrescue deblaze dex2jar dff dhcpig dictstat dirb dirbuster distorm3 dmitry dnmap dns2tcp dnschef dnsenum \
	dnsmap dnsrecon dnstracer dnswalk doona dos2unix dotdotpwn dradis dumpzilla \
	eapmd5pass edb-debugger enum4linux enumiax exploitdb extundelete \
	fern-wifi-cracker fierce fiked fimap findmyhash firewalk fragroute foremost funkload \
	galleta ghost-fisher giskismet grabber go-lismero goofile gpp-decrypt gsad gsd gqrx guymager gr-scan \
	hamster-sidejack hash-identifier hexinject hexorbase http-tunnel httptunnel hping3 hydra \
	iaxflood inguma intrace inundator inviteflood ipv6-toolkit iphone-backup-analyzer intersect ismtp isr-evilgrade \
	jad javasnoop jboss-autopwn jd-gui john johnny joomscan jsql \
	kalibrate-rtl keepnote killerbee kismet keimpx \
	linux-exploit-suggester ldb lynis \
	maltego-teeth magictree masscan maskgen maskprocessor mdk3 metagoofil metasploit mfcuk mfoc mfterm miranda mitmproxy multiforcer \
	multimon-ng \
	ncrack netcat nishang nipper-ng nmap ntop \
	oclgausscrack ohwurm ollydpg openvas-administrator openvas-cli openvas-manager openvas-scanner oscanner \
	p0f padbuster paros parsero patator pdf-parser pdfid pdgmail peepdf phrasendrescher pipal pixiewps plecost polenum policygen \
	powerfuzzer powersploit protos-sip proxystrike pwnat \
	rcrack rcrack-mt reaver rebind recon-ng redfang regripper responder ridenum rsmangler rtlsdr-scanner rtpbreak rtpflood rtpinsertsound \
	rtpmixsound \
	sakis3g sbd sctpscan setoolkit sfuzz shellnoob sidguesser siparmyknife sipp sipvicious skipfish slowhttptest smali smtp-user-enum \
	sniffjoke snmpcheck spooftootph sslcaudit sslsplit sslstrip sslyze sqldict sqlmap sqlninja sqlsus statprocessor \
	t50 termineter thc-hydra thc-ipv6 thc-pptp-bruter thc-ssl-dos tnscmd10g truecrack theharverster tlssled twofi \
	u3-pwn uatester urlcrazy uniscan unix-privesc-check vega w3af webscarab webshag webshells webslayer websploit weevely wfuzz wifi-honey \
	wifitap wifite wireshark winexe wpscan wordlists valgrind volatility voiphopper wol-e xspy xplico xsser yara yersinia zaproxy
    echo "$(tput setaf 2)Hacking tools should be removed now$(tput sgr0)"
}

check_no_pass()
{
    sed -i s/NOPASSWD:// /etc/sudoers
    echo "$(tput setaf 2)Removed any instances of NOPASSWD in sudoers$(tput sgr0)"
}

edit_passwd_policy()
{
	if grep -q "minlen" "/etc/pam.d/common-password"; then
		sed -i 's/minlen=.*/minlen=12/' "/etc/pam.d/common-password"
	else
		sed -i 's/sha512/sha512 minlen=12/' "/etc/pam.d/common-password"
	fi
	
	sed -i.bak -e 's/PASS_MAX_DAYS\t[[:digit:]]\+/PASS_MAX_DAYS\t30/' /etc/login.defs
    	sed -i -e 's/PASS_MIN_DAYS\t[[:digit:]]\+/PASS_MIN_DAYS\t7/' /etc/login.defs
    	sed -i -e 's/PASS_WARN_AGE\t[[:digit:]]\+/PASS_WARN_AGE\t14/' /etc/login.defs
	
	check_no_pass
}

disable_root_account()
{
  passwd -l root
}

disable_guest_account()
{
    echo 'allow-guest=false' >> /etc/lightdm/lightdm.conf
}

#### Main


if [ $(id -u) != "0" ]; then
{
	echo "$(tput setaf 1)Please run as superuser$(tput sgr0)"
	exit 1
}
else
{
	echo "$(tput setaf 2)Let's do this$(tput sgr0)"
}
fi

echo "$(tput setaf 2)Printing BeforeRunning HTML page${reset}"
write_page > BeforeRunning.html

echo "$(tput setaf 2)Making sure only root has uid 0$(tput sgr0)"
preserve_root_uid

echo "$(tput setaf 2)Setting up users and passwords. Make sure to fix Admin passwords!${reset}"
set_users
set_passwords

echo "$(tput setaf 2)Setting update settings$(tput sgr0)"
set_update_settings

echo "$(tput setaf 2)Updating$(tput sgr0)"
apt-get update --force-yes -y
echo "$(tput setaf 2)Upgrading$(tput sgr0)"
apt-get upgrade --force-yes -y

echo "$(tput setaf 2)Firefox is sometimes a little stubborn and won't update with everyone else.$(tput sgr0)"
apt-get --purge --reinstall install firefox
echo "$(tput setaf 2)Same with Libre Office$(tput sgr0)"
echo "$(tput setaf 2)Adding Libre Office repository$(tput sgr0)"
add-apt-repository -y ppa:libreoffice/ppa
echo "$(tput setaf 2)Updating again$(tput sgr0)"
apt-get update
echo "$(tput setaf 2)Installing Libre Office$(tput sgr0)"
sudo apt-get --purge --reinstall install libreoffice
echo "$(tput setaf 2)Install Cracklib$(tput sgr0)"
sudo apt-get install libpam-cracklib --force-yes -y

echo "$(tput setaf 2)Updates are done!$(tput sgr0)"
echo "$(tput setaf 2)Time to do password policy$(tput sgr0)"
edit_passwd_policy
echo "$(tput setaf 2)Done with password policy!$(tput sgr0)"

echo "$(tput setaf 2)Disabling root ssh login$(tput sgr0)"
disable_ssh_root_login

echo "$(tput setaf 2)Disabling Guest account$(tput sgr0)"
disable_guest_account

echo "$(tput setaf 2)Disabling root account$(tput sgr0)"
disable_root_account

echo "$(tput setaf 2)Removing common hacking tools$(tput sgr0)"
remove_hacking_tools

echo "$(tput setaf 2)Starting firewall$(tput sgr0)"
ufw enable

echo "$(tput setaf 2)Generating post-script HTML file$(tput sgr0)"
write_page > AfterRunning.html

echo "$(tput setaf 2)Finished everything else, time to run Clam$(tput sgr0)"
if [[ ! -d "/home/VIRUS" ]]
then
        if [[ ! -L "/home/VIRUS" ]]
        then
                echo "Directory doesn't exist. Creating now"
                mkdir "/home/VIRUS"
                echo "Directory created"
        else
                echo "Directory exists"
        fi
fi
apt-get install clamav
freshclam
echo "$(tput setaf 2)Scan started$(tput sgr0)"
clamscan -r --bell -i --move=/home/VIRUS /

echo "$(tput setaf 2)Scan done. Generating post-scan HTML file$(tput sgr0)"
write_page > AfterRunningScan.html

echo "$(tput setaf 2)And I suggest double checking common-password in /etc/pam.d and /etc/login.defs${reset}"
echo "$(tput setaf 2)Also, double check cron jobs, update settings, and programs/processes that exist but shouldn't.$(tput sgr0)"
echo "$(tput setaf 2)Also, configure iptables. The requirements will be implied in the readme on the desktop, and will be different for every round.$(tput sgr0)"

exit 0


# Ubuntu Security Script
# Brian Strauch

if [[ $EUID -ne 0 ]]
then
  echo "You must be root to run this script."
  exit 1
fi

# Firewall
sudo ufw enable

# Updates
sudo apt-get -y upgrade
sudo apt-get -y update

# Lock Out Root User
sudo passwd -l root

# Disable Guest Account
echo "allow-guest=false" >> /etc/lightdm/lightdm.conf

# Configure Password Aging Controls
sudo sed -i '/^PASS_MAX_DAYS/ c\PASS_MAX_DAYS   90' /etc/login.defs
sudo sed -i '/^PASS_MIN_DAYS/ c\PASS_MIN_DAYS   10'  /etc/login.defs
sudo sed -i '/^PASS_WARN_AGE/ c\PASS_WARN_AGE   7' /etc/login.defs

# Password Authentication
sudo sed -i '1 s/^/auth optional pam_tally.so deny=5 unlock_time=900 onerr=fail audit even_deny_root_account silent\n/' /etc/pam.d/common-auth

# Force Strong Passwords
sudo apt-get -y install libpam-cracklib
sudo sed -i '1 s/^/password requisite pam_cracklib.so retry=3 minlen=8 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1\n/' /etc/pam.d/common-password

# MySQL
echo -n "MySQL [Y/n] "
read option
if [[ $option =~ ^[Yy]$ ]]
then
  sudo apt-get -y install mysql-server
  # Disable remote access
  sudo sed -i '/bind-address/ c\bind-address = 127.0.0.1' /etc/mysql/my.cnf
  sudo service mysql restart
else
  sudo apt-get -y purge mysql*
fi

# OpenSSH Server
echo -n "OpenSSH Server [Y/n] "
read option
if [[ $option =~ ^[Yy]$ ]]
then
  sudo apt-get -y install openssh-server
  # Disable root login
  sudo sed -i '/^PermitRootLogin/ c\PermitRootLogin no' /etc/ssh/sshd_config
  sudo service ssh restart
else
  sudo apt-get -y purge openssh-server*
fi

# VSFTPD
echo -n "VSFTP [Y/n] "
read option
if [[ $option =~ ^[Yy]$ ]]
then
  sudo apt-get -y install vsftpd
  # Disable anonymous uploads
  sudo sed -i '/^anon_upload_enable/ c\anon_upload_enable no' /etc/vsftpd.conf
  sudo sed -i '/^anonymous_enable/ c\anonymous_enable=NO' /etc/vsftpd.conf
  # FTP user directories use chroot
  sudo sed -i '/^chroot_local_user/ c\chroot_local_user=YES' /etc/vsftpd.conf
  sudo service vsftpd restart
else
  sudo apt-get -y purge vsftpd*
fi

# Malware
sudo apt-get -y purge hydra*
sudo apt-get -y purge john*
sudo apt-get -y purge nikto*
sudo apt-get -y purge netcat*

# Media Files
for suffix in mp3 txt wav wma aac mp4 mov avi gif jpg png bmp img exe msi bat sh; do
  sudo find /Users -name *.$suffix
done
