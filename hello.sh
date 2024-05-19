#!/bin/bash

# patch for line endings issue:
# sed -i -e 's/\r$//' ubuntu.sh

# ==== Prepare ====
log_file="script_log.txt"
AlteredConfigLoc="AlteredConfigs.txt"

# Check if the script is being run as root
if [ "$EUID" -ne 0 ]; then
    echo "This script requires root (sudo). Attempting to re-run with sudo..."
    sudo "$0" "$@"
    exit $? # Exit after running itself as sudo
fi

# predefined variables
newPassword="Cyb3rP@tri0t"
whitelistedServices=("sysstat" "usbguard" "usbguard-dbus" "netfilter-persistent" "psad" "anacron" "haveged" "auditd" "acct" "fail2ban" "gdm3" "open-vm-tools" "acpid" "apparmor" "apport" "avahi-daemon" "ccsclient" "checkfs.sh" "checkroot-bootclean.sh" "checkroot.sh" "console-setup" "cron" "cups" "cups-browsed" "dbus" "dns-clean" "grub-common" "hostname.sh" "hwclock.sh" "irqbalance" "kerneloops" "killprocs" "kmod" "lightdm" "mountall-bootclean.sh" "mountall.sh" "mountdevsubfs.sh" "mountkernfs.sh" "mountnfs-bootclean.sh" "mountnfs.sh" "network-manager" "networking" "nmbd" "ondemand" "openbsd-inetd" "plymouth" "plymouth-log" "pppd-dns" "procps" "rc.local" "resolvconf" "rsyslog" "speech-dispatcher" "udev" "ufw" "umountfs" "umountnfs.sh" "umountroot" "unattended-upgrades" "urandom" "uuidd" "vmware-tools" "vmware-tools-thinprint" "whoopsie" "x11-common")
whitelistedSoftware=("upower")
whitelistedSoftware+=$whitelistedServices
blacklistedSoftware=("rhythmbox" "aisleriot" "gnome-mahjongg" "gnome-mines" "gnome-sudoku" "mahjongg" "ace-of-penguins" "gnomine" "gbrainy" "rsh-client" "talk" "telnet" "nmap" "zenmap" "samba" "remmina" "shotwell" "ophcrack" "cheese" "pulseaudio" "pavucontrol" "totem" "usb-creator-gtk" "simple-scan" "baobab" "evince" "eog" "seahorse" "gnome-todo" "wireshark" "transmission" "transmission-daemon" "transmission-cli" "transmission-gtk") # list of never-wanted software that has been installed before

# prepare
mkdir /etc/backups 2> /dev/null
cd /home/$SUDO_USER
IP=$(hostname -I | awk '{print $1}')

if [ ! -e ./CompletedQuestions.txt ]; then
    read -p "Have you completed the forensic questions? [y/N]: " finishedQuestions    
    if [[ $finishedQuestions == *y* ]]; then echo -e "Proceeding\n-----"; else echo "Do those first - exiting..." && exit; fi
    echo "Used to indicate in my script whether you said yes to completing forensic questions already" > "CompletedQuestions.txt"
fi

installAll() { #install list of packages without crashing if one is not found
  package_string="$1"
  packages=($package_string)
  for package in "${packages[@]}"; do
    sudo apt install -y "$package"
  done
}

log() {
  local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
  echo "[$timestamp] $1" >> "$log_file"
}

onExit() {
    echo -e "\n"
    # Close log file
    echo "Script finished at $(date)" >> "$log_file"
    exec > /dev/tty 2>&1

    cd /home/$SUDO_USER
    echo -e "\n\n\n"
    echo "============================================================"
    echo "Check 'service --status-all' for suspicious running services"
    echo "Check 'sudo crontab -l' for malicous scripts"
    echo "Check 'ls /etc/init.d/'"
    echo "Check for malware in '~/.bashrc', '~/.bash_profile', '/etc/bash.bashrc'"
    echo "Check packages where debsums failed (see $AlteredConfigLoc)"
    echo "If SSH, check '~/.ssh/authorized_keys'"
}

install_aval_package() {
    packages=""
    for i in $1
    do 
        if [ -z "$(apt-cache policy $i 2>/dev/null)" ]; then
            echo "WARN> Package $i not available on repo."
        else
            # echo " > Added package $i to the install list"
            packages="$packages $i"
        fi
    done
    echo "Installing: $packages"
    # sudo apt install $packages -y --fix-broken --ignore-hold # --force-yes
    sudo aptitude install $packages -y -f 

    # sudo dpkg -i <package-name>
}


# local config "files"
userParsePythonCode=$(cat <<END
text = """
<readme>
"""
admins = text[text.index("Authorized Administrators:") : text.index("Authorized Users:")]
htmlIndex = admins.index(">")
newlineIndex = admins.index("\n")
admins = admins[(htmlIndex if htmlIndex < newlineIndex else newlineIndex)+1:]
admins = admins[:admins.index("<")]
admins = admins.strip()
lines = admins.split("\n")
admins = ""
for line in lines:
    line = line.strip()
    if (not line.startswith("password")):
        admins += line.split(' ')[0] + " "
print(admins+" | ")

users = text[text.index("Authorized Users:"):]
htmlIndex = users.index(">")
newlineIndex = users.index("\n")
users = users[(htmlIndex if htmlIndex < newlineIndex else newlineIndex)+1:]
users = users[:users.index("<")]
users = users.strip()
lines = users.split("\n")
users = ""
for line in lines:
    users += line + " "
print(users)
END
)
unattendedUpgrades=$(cat <<EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id} stable";
    "\${distro_id} \${distro_codename}-security";
    "\${distro_id} \${distro_codename}-updates";
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Package-Blacklist {}
Unattended-Upgrade::InstallOnShutdown "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
Unattended-Upgrade::DevRelease "auto";
EOF
)
periodic10=$(cat <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
)
grubConfig=$(cat <<EOF
set superusers="$SUDO_USER"
password_pbkdf2 $SUDO_USER <grubpass>
EOF
)
sslParams=$(cat <<EOF
SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH
SSLProtocol All -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
SSLHonorCipherOrder On
# Disable preloading HSTS for now.  You can use the commented out header line that includes
# the "preload" directive if you understand the implications.
# Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
Header always set X-Frame-Options DENY
Header always set X-Content-Type-Options nosniff
# Requires Apache >= 2.4
SSLCompression off
SSLUseStapling on
SSLStaplingCache "shmcb:logs/stapling-cache(150000)"
# Requires Apache >= 2.4.11
SSLSessionTickets Off
EOF
)
defaultSSL=$(cat <<EOF
<IfModule mod_ssl.c>
        <VirtualHost _default_:443>
                ServerAdmin fakeEmail@gmail.com
                ServerName $IP
                DocumentRoot /var/www/html
                ErrorLog ${APACHE_LOG_DIR}/error.log
                CustomLog ${APACHE_LOG_DIR}/access.log combined
                SSLEngine on
                SSLCertificateFile      /etc/ssl/certs/apache-selfsigned.crt
                SSLCertificateKeyFile /etc/ssl/private/apache-selfsigned.key
                <FilesMatch "\.(cgi|shtml|phtml|php)$">
                                SSLOptions +StdEnvVars
                </FilesMatch>
                <Directory /usr/lib/cgi-bin>
                                SSLOptions +StdEnvVars
                </Directory>
        </VirtualHost>
</IfModule>
EOF
)
vsftpConfig="
auth       required     pam_userdb.so db=/etc/vsftpd/vsftpd-virtual-user
account    required     pam_userdb.so db=/etc/vsftpd/vsftpd-virtual-user
session    required     pam_loginuid.so"

ftpConfig="
listen=NO
listen_ipv6=YES
anonymous_enable=NO
local_enable=YES
root_login_enable=NO
local_root=/var/run/vsftpd/empty
write_enable=YES
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
#nopriv_user=ftpsecure
ftpd_banner=Welcome to blah FTP service.
secure_chroot_dir=/var/run/vsftpd/empty
chroot_local_user=YES
allow_writeable_chroot=YES
hide_ids=YES
# Virtual User Settings
user_config_dir=/etc/vsftpd/vsftpd_user_conf
guest_enable=YES
virtual_use_local_privs=YES
pam_service_name=vsftpd
nopriv_user=vsftpd
guest_username=vsftpd
# Other
pam_service_name=vsftpd
rsa_cert_file=/etc/vsftpd/vsftpd.pem
rsa_private_key_file=/etc/vsftpd/vsftpd.key
ssl_enable=YES
allow_anon_ssl=NO
force_local_data_ssl=YES
force_local_logins_ssl=YES
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
pasv_min_port=7000
pasv_max_port=7500"
tlsConfig="
<IfModule mod_tls.c>
TLSEngine                               on
TLSLog                                  /var/log/proftpd/tls.log
TLSProtocol                             SSLv23

TLSRSACertificateFile                   /etc/ssl/certs/proftpd.crt
TLSRSACertificateKeyFile                /etc/ssl/private/proftpd.key

#TLSCACertificateFile                                     /etc/ssl/certs/CA.pem
TLSOptions                      NoCertRequest EnableDiags NoSessionReuseRequired
TLSVerifyClient                         off
TLSRequired                             on
TLSRenegotiate                          required on
</IfModule>"

proftpConfig="
Include /etc/proftpd/modules.conf
UseIPv6 on
RequireValidShell on
AuthOrder mod_auth_pam.c* mod_auth_unix.c
<IfModule mod_ident.c>
  IdentLookups off
</IfModule>
ServerName "Ubuntu"
ServerType standalone
DeferWelcome off
DefaultServer on
ShowSymlinks on
TimeoutNoTransfer 600
TimeoutStalled 600
TimeoutIdle 200
DisplayLogin welcome.msg
DisplayChdir .message true
ListOptions "-l"
DenyFilter \*.*/
DefaultRoot ~
Port 21
<IfModule mod_dynmasq.c>
</IfModule>
MaxInstances 2
User proftpd
Group nogroup
Umask 027 027
AllowOverwrite on
TransferLog /var/log/proftpd/xferlog
SystemLog /var/log/proftpd/proftpd.log
<IfModule mod_quotatab.c>
QuotaEngine off
</IfModule>
<IfModule mod_ratio.c>
Ratios off
</IfModule>
<IfModule mod_delay.c>
DelayEngine on
</IfModule>
<IfModule mod_ctrls.c>
ControlsEngine off
ControlsMaxClients 2
ControlsLog /var/log/proftpd/controls.log
ControlsInterval 5
ControlsSocket /var/run/proftpd/proftpd.sock
</IfModule>
<IfModule mod_ctrls_admin.c>
AdminControlsEngine off
</IfModule>
Include /etc/proftpd/tls.conf
Include /etc/proftpd/sftp.conf
Include /etc/proftpd/conf.d/"

sourcesListUbuntu="
deb http://us.archive.ubuntu.com/ubuntu/ trusty main restricted universe multiverse
deb http://us.archive.ubuntu.com/ubuntu/ trusty-security main restricted universe multiverse
deb http://us.archive.ubuntu.com/ubuntu/ trusty-updates main restricted universe multiverse

deb http://security.ubuntu.com/ubuntu/ jammy-security universe main
deb http://archive.ubuntu.com/ubuntu jammy-backports universe main
deb http://archive.ubuntu.com/ubuntu jammy main universe
deb http://archive.ubuntu.com/ubuntu jammy-updates main restricted universe multiverse
            
deb https://deb.debian.org/debian/ bookworm main contrib non-free-firmware
deb-src https://deb.debian.org/debian/ bookworm main contrib non-free-firmware #Added by software-properties
"
sourcesListDebian="
deb http://deb.debian.org/debian bookworm main contrib non-free
deb-src http://deb.debian.org/debian bookworm main contrib non-free

deb http://deb.debian.org/debian-security/ bookworm-security main contrib non-free
deb-src http://deb.debian.org/debian-security/ bookworm-security main contrib non-free

deb http://deb.debian.org/debian bookworm-updates main contrib non-free
deb-src http://deb.debian.org/debian bookworm-updates main contrib non-free
"

LockdownConf80="
v4.conf.all.accept_source_route: 0
net.ipv6.conf.all.accept_source_route: 0
net.ipv4.conf.default.accept_source_route: 0
net.ipv6.conf.default.accept_source_route: 0
net.ipv4.conf.all.accept_redirects: 0
net.ipv6.conf.all.accept_redirects: 0
net.ipv4.conf.default.accept_redirects: 0
net.ipv6.conf.default.accept_redirects: 0
net.ipv4.conf.all.secure_redirects: 1
net.ipv4.conf.default.secure_redirects: 1
net.ipv4.ip_forward: 0
net.ipv6.conf.all.forwarding: 0
net.ipv4.conf.all.send_redirects: 0
net.ipv4.conf.default.send_redirects: 0
net.ipv4.conf.all.rp_filter: 1
net.ipv4.conf.default.rp_filter: 1
net.ipv4.icmp_echo_ignore_broadcasts: 1
net.ipv4.icmp_ignore_bogus_error_responses: 1
net.ipv4.icmp_echo_ignore_all: 0
net.ipv4.conf.all.log_martians: 1
net.ipv4.conf.default.log_martians: 1
net.ipv4.tcp_rfc1337: 1
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
kernel.randomize_va_space: 2
fs.protected_hardlinks: 1
fs.protected_symlinks: 1
kernel.perf_event_paranoid: 2
kernel.core_uses_pid: 1
kernel.kptr_restrict: 2
kernel.modules_disabled: 1
kernel.sysrq: 0
kernel.yama.ptrace_scope: 1
"
pwquality="
difok = 8
dictcheck = 1
enforcing = 1
maxrepeat = 3
minclass = 3
minlen = 12
dcredit = -1
lcredit = -1
ocredit = -1
ucredit = -1
"

initpath="
if [[ \$EUID -eq 0 ]]; then
  export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
else
  export PATH=/usr/local/bin:/usr/sbin:/usr/bin:/bin:/snap/bin
fi
"

# begin
while true; do
    cd /home/$SUDO_USER
    clear
    echo "--- Options --- (times are hopefully as worst-case scenario)"
    echo "1.  Configure apt                                             - 920s"
    echo "1.2.   Install required packages                              - 920s"
    echo "2.  Scan for altered config files                             - 45s"
    echo "3.  Run konstruktoid/hardening (ubuntu only)                  - 700s"
    echo "4.  Audit users                                               - 10s"
    echo "5.  Set account/system policies                               - 0s"
    echo "6.  Set up auditing                                           - 10s"
    echo "7.  Setup firewall                                            - 10s"
    echo "8.  Configure services                                        "
    echo "9.  Configure firefox                                         "
    echo "10. Remove unathorized software                               "
    echo "11. Kernal hardening                                          "
    echo "12. Miscellaneous hardening                                   "
    echo "13. SSH hardening                                             "
    echo "14. Filesystem hardening                                      "
    echo "15. FTP hardening (wip)                                       "
    echo "16. Webserver (nginx, apache) hardening (wip)                 "
    echo "17. Install gnome extensions                                  "
    echo "17.1. Apply gnome extensions                                  "
    echo "98. Audit (score) system                                      "
    echo "99. Pre-exiting (cleanup + reenable inconvinient settings)    "
    echo "exit: Quit                                                    "
    echo ""
    read -p "Number to run: " choice

    start_time=$(date +%s)

    case $choice in
        1)  # apt
            echo -e "---\nConfiguring updates and apt"
            echo "$unattendedUpgrades" >> /etc/apt/apt.conf.d/50unattended-upgrades

            # Configure update notifications
            echo "$periodic10" > /etc/apt/apt.conf.d/10periodic

            # Configure sources.list
            if [ -f "/etc/apt/apt.conf.d/20apt-esm-hook.conf" ]; then
                sudo rm /etc/apt/apt.conf.d/20apt-esm-hook.conf # Remove the "look what you get when you subscribe" spam when upgrading
            fi
            echo "Updating apt sources.list"
            sudo echo "$sourcesListDebian" | sudo tee /etc/apt/sources.list

            sudo apt update
            # installAll "debsums curl iptables-persistent fail2ban git openssl db-util net-tools procps update-notifier unattended-upgrades apt-show-versions rsyslog apparmor apt-listbugs apparmor-profiles apparmor-utils apt-listchanges needrestart debsecan debsums libpam-cracklib aide usbguard acct auditd -y"
            ;;
        1.2) # install packages
            # install and use aptitude, it works a little better
            sudo apt install aptitude
            install_aval_package "aptitude ufw auditd gedit debsums curl fail2ban git openssl db-util net-tools procps update-notifier unattended-upgrades apt-show-versions rsyslog apparmor apt-listbugs apparmor-profiles apparmor-utils apt-listchanges needrestart debsecan debsums libpam-cracklib aide usbguard psad acct systemd-resolved rkhunter"
            # iptables-persistent netfilter-persistent
            # dpkg-reconfigure -plow unattended-upgrades
            ;;
        2)  # debsums
            # check if a scan file already exists
            if [ -e $file ]; then
                timestamp=$(date +"%H-%M-%S")
                new_filename="${AlteredConfigLoc%.*}-($timestamp).bak"
                echo "Moving old results file to $new_filename"
                mv "$AlteredConfigLoc" "$new_filename"
            fi
            echo -e "---\nScanning for non-default configureation files..."
            # sudo debsums -e | grep --line-buffered "FAILED"
            sudo debsums -e | tee >(grep --line-buffered "FAILED") > tempAltConfigs.txt # save command results to file since it takes a while to run
            cat tempAltConfigs.txt | grep "FAILED" > $AlteredConfigLoc # filter file to just failed
            log "$(cat tempAltConfigs.txt)"
            rm tempAltConfigs.txt
            echo ""
            echo "These packages have non-stadard configuration files, and could have been altered by cyberpatriot. Look over the configurations and consider hardening/reinstalling"
            echo "Results saved in $(pwd)/$AlteredConfigLoc"
            ;;
        3)  # konstruktoid/hardening
            echo "Running konstruktoid/hardening"
            git clone https://github.com/konstruktoid/hardening.git
            cd hardening
            sed -i s/CHANGEME=\'\'/CHANGEME=\'nah\'/ ubuntu.cfg #forces this to run smh
            # Prevent AIDE from starting yet, it takes too long - TODO: init aide at end of script
            sudo sed -i 's/aideinit --yes/aideinit --yes -b/' ./scripts/aide
            # sed -i '/^TIMESYNCD/d' ubuntu.cfg # Make sure it does not screw up the TZ, but removing this makes it not work
            chmod +x *.sh
            sudo bash ./ubuntu.sh
            # disable scanning apt packages, as it takes longer
            RKHUNTERCONF='/etc/default/rkhunter'
            sudo sed -i 's/^APT_AUTOGEN=.*/APT_AUTOGEN="no"/' "$RKHUNTERCONF"
            sudo rkhunter --propupd
            echo -e "\n\nCompleted konstruktoid/hardening"
            ;;
        4)  # users
            echo "Starting user aduit"
            echo -e "---\nParsing out allowed users"
            user=$(whoami)
            allUsers=$(grep '^[^:]*:[^:]*:[0-9]\{4,\}' /etc/passwd | cut -d: -f1)

            readmeURL=$(cat /home/$SUDO_USER/Desktop/README.desktop | grep -Po "http.+(?=\")")
            echo "Fetching README from $readmeURL"
            readme=$(curl $readmeURL)

            # Speant hours trying to parse it out in bash, let's just use python =P (this took 5 min lol)
            codeWithReadme=$(echo "$userParsePythonCode" | awk -v readme="$readme" '{gsub(/<readme>/, readme)}1')

            output=$(python3 -c "$codeWithReadme")

            admins=($(echo "${output%%|*}"))
            users=($( echo "${output#*|}"))

            # admins=("korra" "mako" "bolin" "asami" "lin")
            # users=("jinora" "ikki" "meelo" "opal" "kai" "bumi" "kya" "suyin" "pema" "tarrlok" "varrick" "iroh" "wu" "raava" "gommu" "yung" "raiko" "desna" "eska")

            
            parsingDone=false
            while ! $parsingDone; do

                echo -e "---\nParsed users"
                echo "Sudoers: ${admins[@]}"
                echo "Users: ${users[@]}"
                read -p "Does this look parsed correctly? [Y/n]: " parsedCorrectly
                
                # Allow manual
                if [[ $parsedCorrectly == *n* ]]; then 
                    echo "<Comma separated users>" > ~/users.txt
                    echo "<Comma separated administrators>" > ~/admins.txt
                    nano ~/users.txt
                    nano ~/admins.txt
                    users_file=$(cat ~/users.txt)
                    admins_file=$(cat ~/admins.txt)
                    users_file=$(echo "$users_file" | sed -e 's/[ \t]*//g')
                    admins_file=$(echo "$admins_file" | sed -e 's/[ \t]*//g')
                    IFS=',' read -ra users <<< "$users_file"
                    IFS=',' read -ra admins <<< "$admins_file"
                else
                    parsingDone=true
                fi
            done

                # echo -e "\n---\nSkipping auto-configuring users"
            log "Current users: $allUsers"
            log "Allowed admins: $admins" 
            log "Allowed users: $users" 
            
            echo -e "Continuing to auto-configure users\n---"
            for username in $allUsers; do
                if [ "$username" != "nobody" ]; then # nobody seems to be a default ubuntu account
                    #check if is in user array
                    if [[ " ${users[*]} " == *" $username "* ]]; then
                        # check if he has illegal perms
                        if sudo -l -U "$username" | grep -q "(ALL : ALL)"; then
                            # he is an admin and should not be
                            echo "User $username should not be sudo"
                            read -p "Remove sudo from $username? [Y/n]: " removeSudo
                            if [[ $removeSudo != *n* ]]; then
                                log "Removed sudo from $username"
                                sudo deluser $username sudo
                            fi
                        fi
                    else
                        # if he is not a user, see if he is an admin
                        if [[ " ${admins[*]} " == *" $username "* ]]; then
                            # check if he is missing perms
                            if ! sudo -l -U "$username" | grep -q "(ALL : ALL)"; then
                                echo "Admin $username should have sudo rights"
                                read -p "Add $username to sudo users? [Y/n]: " addSudo
                                if [[ $addSudo != *n* ]]; then 
                                    log "Added sudo to $username"
                                    sudo adduser $username sudo
                                fi
                            fi
                        else
                            echo "User $username does not belong."
                            read -p "Delete $username? [Y/n]: " removeUser
                            if [[ $removeUser != *n* ]]; then 
                                log "Deleting $username"
                                sudo killall -u $username
                                sudo userdel -r -f $username
                                echo -e "(ignore mail errors)\n---"
                            fi
                        fi
                    fi
                fi
            done

            # reset all users now that we removed some
            allUsers=$(grep '^[^:]*:[^:]*:[0-9]\{4,\}' /etc/passwd | cut -d: -f1)
            log "Current user are now $allUsers"

            # Use harder password hash format
            sudo sed -i 's/password.*pam_unix.so.*/password	[success=2 default=ignore] pam_unix.so obscure use_authtok try_first_pass sha512/' /etc/pam.d/common-password
            # Check if the file contains "sha512"
            if grep -q "sha512" "/etc/pam.d/common-password"; then
                echo "Set password algorithm to sha512"
            else
                echo "sha512 is not in '/etc/pam.d/common-password' after configuring, check if '/etc/security/opasswd' contains the password instead"
            fi

            # reset all user passwords. A bit extreme but it works
            echo -e "Resetting all user passwords (but yours)\n---"
            # user="$(whoami)" # whoami returns "root" when run as admin
            user=$SUDO_USER # SUDO_USER is built-into linux

            encryptedPassword=$(echo $newPassword | openssl passwd -1 -stdin)
            for username in $allUsers; do
                # Skip changing password for your own username
                if [ "$username" != "$user" ]; then
                    echo "Changing password for: $username"
                    sudo usermod --password $encryptedPassword $username
                    log "Changed password for: $username"
                fi
            done

            echo -e "\n---\nDisabling root and system account\n---"
            sudo passwd -l root
            sudo usermod -L root # in case passwd was poisoned
            sudo passwd -l daemon
            sudo passwd -l bin
            sudo passwd -l sys
            sudo passwd -l sync
            sudo passwd -l games
            sudo passwd -l man
            sudo passwd -l lp
            sudo passwd -l mail
            sudo passwd -l news
            sudo passwd -l uucp
            sudo passwd -l proxy
            sudo passwd -l backup
            sudo passwd -l list
            sudo passwd -l irc
            sudo passwd -l _apt
            sudo passwd -l systemd-network
            sudo passwd -l tss
            sudo passwd -l systemd-timesync
            sudo passwd -l messagebus
            sudo passwd -l usbmux
            sudo passwd -l dnsmasq
            sudo passwd -l avahi
            sudo passwd -l speech-dispatcher
            sudo passwd -l rtkit
            sudo passwd -l colord
            sudo passwd -l polkitd
            sudo passwd -l geoclue
            sudo passwd -l saned
            sudo passwd -l fwupd-refresh
            sudo passwd -l www-data
            sudo passwd -l Debian-gdm
            sudo passwd -l gnome-initial-setup
            
            sudo passwd -l nobody
            sudo userdel -r nobody 2> /dev/null

            # Remove any perms from nobody user


            echo "Disabling root ssh account (if ssh is installed)"
            sshConfigLoc="/etc/ssh/sshd_config"
            if [ ! -f "$sshConfigLoc" ]; 
            then
                echo "SSH configuration file not found: $sshConfigLoc"
            else
                sudo cp "$sshConfigLoc" "$sshConfigLoc.bak"
                sudo sed -i 's/^PermitRootLogin yes$/PermitRootLogin no/' "$sshConfigLoc"
                sudo service ssh restart
                echo "Disabled ssh root login"
            fi;

            # Make sure shadow file matches group file
            sudo grpconv


            ;;
        5)  # policies
            echo -e "---\nEnforcing password policy\n---"
            RETRY=5
            MINLEN=12
            MINCLASS=3
            DIFOK=3
            PAM_CONFIG="/etc/pam.d/common-password"  # Update this path if needed
            sudo cp "$PAM_CONFIG" "$PAM_CONFIG.backup"

            # restrict login
            echo -e "---\nRestricting login settings\n---"
            sed -i 's/^.*LOG_OK_LOGINS.*/LOG_OK_LOGINS yes/' "/etc/login.defs"
            sed -i 's/^UMASK.*/UMASK 077/' "/etc/login.defs"
            sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' "/etc/login.defs"
            sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' "/etc/login.defs"
            sed -i 's/DEFAULT_HOME.*/DEFAULT_HOME no/' "/etc/login.defs"
            sed -i 's/ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' "/etc/login.defs"
            sed -i 's/USERGROUPS_ENAB.*/USERGROUPS_ENAB no/' "/etc/login.defs"
            sed -i 's/^#.*SHA_CRYPT_MIN_ROUNDS .*/SHA_CRYPT_MIN_ROUNDS 10000/' "/etc/login.defs"
            sed -i 's/^#.*SHA_CRYPT_MAX_ROUNDS .*/SHA_CRYPT_MAX_ROUNDS 65536/' "/etc/login.defs"

            if [ -f /etc/init.d/rc ]; then
                sed -i 's/umask 022/umask 077/g' /etc/init.d/rc
            fi
            if ! grep -q -i "umask" "/etc/profile" 2> /dev/null; then
                echo "umask 077" >> /etc/profile
            fi
            if ! grep -q -i "umask" "/etc/bash.bashrc" 2> /dev/null; then
                echo "umask 077" >> /etc/bash.bashrc
            fi
            if ! grep -q -i "TMOUT" "/etc/profile.d/*" 2> /dev/null; then
                echo -e 'TMOUT=600\nreadonly TMOUT\nexport TMOUT' > '/etc/profile.d/autologout.sh'
                chmod +x /etc/profile.d/autologout.sh
            fi


            # ctrl + alt + delete
            systemctl mask ctrl-alt-del.target
            sed -i 's/^#CtrlAltDelBurstAction=.*/CtrlAltDelBurstAction=none/' "/etc/systemd/system.conf"

            if ! grep pam_pwhistory.so "/etc/pam.d/common-password"; then
                sed -i '/the "Primary" block/apassword\trequired\t\t\tpam_pwhistory.so\tremember=7' "/etc/pam.d/common-password"
            fi
            echo "$pwquality" > /etc/security/pwquality.conf
            chmod 0644 /etc/security/pwquality.conf
            if grep 'use_authtok try_first_pass sha512' "/etc/pam.d/common-password"; then
                sed -i 's/try_first_pass sha512.*/try_first_pass sha512 rounds=65536/' "/etc/pam.d/common-password"
            fi
            sed -i -E 's/(nullok|nullok_secure)//g' "/etc/pam.d/common-auth"
            if ! grep retry= "/etc/pam.d/common-password"; then
                echo 'password requisite pam_pwquality.so retry=3' >> "/etc/pam.d/common-password"
            fi
            if [ -f "/etc/security/faillock.conf" ]; then
                if ! grep faillock "/etc/security/faillock.conf"; then
                    sed -i 's/^# audit$/audit/' "/etc/security/faillock.conf"
                    sed -i 's/^# local_users_only$/local_users_only/' "/etc/security/faillock.conf"
                    sed -i 's/^# deny.*/deny = 5/' "/etc/security/faillock.conf"
                    sed -i 's/^# fail_interval.*/fail_interval = 900/' "/etc/security/faillock.conf"
                    sed -i '/pam_tally.*/d' "/etc/pam.d/common-account"
                    sed -i 's/auth.*pam_unix.so/auth required pam_faillock.so preauth\nauth [success=1 default=ignore] pam_unix.so\nauth [default=die] pam_faillock.so authfail\nauth sufficient pam_faillock.so authsucc\n/' "/etc/pam.d/common-auth"
                fi
                if ! grep faillock "/etc/pam.d/common-account"; then
                    echo 'account required pam_faillock.so' >> "/etc/pam.d/common-account"
                fi
            else
                if ! grep tally2 "/etc/pam.d/common-auth"; then
                    sed -i '/^$/a auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900' "/etc/pam.d/common-auth"
                    sed -i '/pam_tally/d' "/etc/pam.d/common-account"
                fi
                if ! grep tally2 "/etc/pam.d/common-account"; then
                    sed -i '/^$/a account required pam_tally2.so' "/etc/pam.d/common-account"
                fi
            fi

            sed -i 's/pam_lastlog.so.*/pam_lastlog.so showfailed/' "/etc/pam.d/login"
            sed -i 's/delay=.*/delay=4000000/' "/etc/pam.d/login"
            curl https://raw.githubusercontent.com/konstruktoid/hardening/master/misc/passwords.list -o /usr/share/dict/passwords
            grep -v '^$' /usr/share/dict/passwords | strings > /usr/share/dict/passwords_text # no idea
            update-cracklib



            ;;
        6)  # auditing
            echo -e "---\nConfiguring auditing\n---"
            echo "
            # Remove any existing rules
            -D

            # Buffer Size
            # Might need to be increased, depending on the load of your system.
            -b 8192

            # Failure Mode
            # 0=Silent
            # 1=printk, print failure message
            # 2=panic, halt system
            -f 1

            # Audit the audit logs.
            -w /var/log/audit/ -k auditlog

            ## Auditd configuration
            ## Modifications to audit configuration that occur while the audit (check your paths)
            -w /etc/audit/ -p wa -k auditconfig
            -w /etc/libaudit.conf -p wa -k auditconfig
            -w /etc/audisp/ -p wa -k audispconfig

            # Schedule jobs
            -w /etc/cron.allow -p wa -k cron
            -w /etc/cron.deny -p wa -k cron
            -w /etc/cron.d/ -p wa -k cron
            -w /etc/cron.daily/ -p wa -k cron
            -w /etc/cron.hourly/ -p wa -k cron
            -w /etc/cron.monthly/ -p wa -k cron
            -w /etc/cron.weekly/ -p wa -k cron
            -w /etc/crontab -p wa -k cron
            -w /var/spool/cron/crontabs/ -k cron

            ## user, group, password databases
            -w /etc/group -p wa -k etcgroup
            -w /etc/passwd -p wa -k etcpasswd
            -w /etc/gshadow -k etcgroup
            -w /etc/shadow -k etcpasswd
            -w /etc/security/opasswd -k opasswd

            # Monitor usage of passwd command
            -w /usr/bin/passwd -p x -k passwd_modification

            # Monitor user/group tools
            -w /usr/sbin/groupadd -p x -k group_modification
            -w /usr/sbin/groupmod -p x -k group_modification
            -w /usr/sbin/addgroup -p x -k group_modification
            -w /usr/sbin/useradd -p x -k user_modification
            -w /usr/sbin/usermod -p x -k user_modification
            -w /usr/sbin/adduser -p x -k user_modification

            # Login configuration and stored info
            -w /etc/login.defs -p wa -k login
            -w /etc/securetty -p wa -k login
            -w /var/log/faillog -p wa -k login
            -w /var/log/lastlog -p wa -k login
            -w /var/log/tallylog -p wa -k login

            # Network configuration
            -w /etc/hosts -p wa -k hosts
            -w /etc/network/ -p wa -k network

            ## system startup scripts
            -w /etc/inittab -p wa -k init
            -w /etc/init.d/ -p wa -k init
            -w /etc/init/ -p wa -k init

            # Library search paths
            -w /etc/ld.so.conf -p wa -k libpath

            # Kernel parameters and modules
            -w /etc/sysctl.conf -p wa -k sysctl
            -w /etc/modprobe.conf -p wa -k modprobe

            # SSH configuration
            -w /etc/ssh/sshd_config -k sshd

            # Hostname
            -a exit,always -F arch=b32 -S sethostname -k hostname
            -a exit,always -F arch=b64 -S sethostname -k hostname

            # Log all commands executed by root
            -a exit,always -F arch=b64 -F euid=0 -S execve -k rootcmd
            -a exit,always -F arch=b32 -F euid=0 -S execve -k rootcmd

            ## Capture all failures to access on critical elements
            -a exit,always -F arch=b64 -S open -F dir=/etc -F success=0 -k unauthedfileacess
            -a exit,always -F arch=b64 -S open -F dir=/bin -F success=0 -k unauthedfileacess
            -a exit,always -F arch=b64 -S open -F dir=/home -F success=0 -k unauthedfileacess
            -a exit,always -F arch=b64 -S open -F dir=/sbin -F success=0 -k unauthedfileacess
            -a exit,always -F arch=b64 -S open -F dir=/srv -F success=0 -k unauthedfileacess
            -a exit,always -F arch=b64 -S open -F dir=/usr/bin -F success=0 -k unauthedfileacess
            -a exit,always -F arch=b64 -S open -F dir=/usr/local/bin -F success=0 -k unauthedfileacess
            -a exit,always -F arch=b64 -S open -F dir=/usr/sbin -F success=0 -k unauthedfileacess
            -a exit,always -F arch=b64 -S open -F dir=/var -F success=0 -k unauthedfileacess

            ## su/sudo
            -w /bin/su -p x -k priv_esc
            -w /usr/bin/sudo -p x -k priv_esc
            -w /etc/sudoers -p rw -k priv_esc

            # Poweroff/reboot tools
            -w /sbin/halt -p x -k power
            -w /sbin/poweroff -p x -k power
            -w /sbin/reboot -p x -k power
            -w /sbin/shutdown -p x -k power

            # Make the configuration immutable
            -e 2
            " > /etc/audit/rules.d/audit.rules
            touch /etc/audit/rules.d/ccdc.rules
            chown root:root /etc/audit/rules.d/ccdc.rules
            echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change | -a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change | -a always,exit -F arch=b64 -S clock_settime -k time-change -a always,exit -F arch=b32 -S clock_settime -k time-change | -w /etc/localtime -p wa -k time-change" >> /etc/audit/rules.d/ccdc.rules # Log modifications to date and time. (2611)
            echo "-w /etc/group -p wa -k identity | -w /etc/passwd -p wa -k identity | -w /etc/gshadow -p wa -k identity | -w /etc/shadow -p wa -k identity | -w /etc/security/opasswd -p wa -k" >> /etc/audit/rules.d/ccdc.rules #Log group modifications (2612)
            echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale   -a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale       -w /etc/issue -p wa -k system-locale          -w /etc/issue.net -p wa -k system-locale           -w /etc/hosts -p wa -k system-locale         -w /etc/network -p wa -k system-locale" >> /etc/audit/rules.d/ccdc.rules #log modifications to host/domain name (2613)
            echo "-w /etc/apparmor/ -p wa -k MAC-policy | -w /etc/apparmor.d/ -p wa -k MAC-policy" >> /etc/audit/rules.d/ccdc.rules # log modifications to AppArmor's Mandatory Acces Controls (2614)
            echo "-w /var/log/faillog -p wa -k logins | -w /var/log/lastlog -p wa -k logins | -w /var/log/tallylog -p wa -k logins" >> /etc/audit/rules.d/ccdc.rules #Collect login/logout information (2615)
            echo "-w /var/run/utmp -p wa -k session | -w /var/log/wtmp -p wa -k logins | -w /var/log/btmp -p wa -k logins" >> /etc/audit/rules.d/ccdc.rules # Collect session initiation info (2616)
            echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod | -a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod | -a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod | -a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod | -a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod | -a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/ccdc.rules #collect file permision changes (2617)
            echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access | -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access | -a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access | -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/ccdc.rules #Collect unsuccessful unauthorized file access attempts (2618)
            echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts | -a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/ccdc.rules #Collect successful File system mounts (2619)
            echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete | -a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/ccdc.rules #Collect file deletion events (2620)
            echo "-w /etc/sudoers -p wa -k scope | -w /etc/sudoers.d/ -p wa -k scope" >> /etc/audit/rules.d/ccdc.rules #Collect modifications to sudoers (2621)
            echo "-w /sbin/insmod -p x -k modules | -w /sbin/rmmod -p x -k modules | -w /sbin/modprobe -p x -k modules | -a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/ccdc.rules # Collect kernel module loading/unloading (2623)
            echo "-e 2" >> /etc/audit/rules.d/99-finalize.rules # Make audit logs immutable. (2624)

            service auditd start
            systemctl enable auditd.service
            service auditd restart

            systemctl --now enable rsyslog
            systemctl --now start rsyslog
            sed -i '/FileCreateMode/c\$FileCreateMode 0640' /etc/rsyslog.conf
            sed -i '/FileCreateMode/c\$FileCreateMode 0640' /etc/rsyslog.d/*.conf 2> /dev/null

            ;;
        7)  # firewall
            echo "Flushing networking cache"
            sudo resolvectl flush-caches
            sudo killall -HUP dnsmasq

            # enforce secure DNS
            sudo sed -i '/DNSSEC=/s/.*/DNSSEC=yes/' /etc/systemd/resolved.conf # TODO: not found
            sudo systemctl restart systemd-resolved


            echo -e "---\nSetting up firewall"
            read -p "Allow SSH [y/N]: " allowSSH
            read -p "Allow FTP [y/N]: " allowFTP
            echo "If other ports are needed, configure them manually"
            sleep 1
            sudo ufw enable
            sudo ufw default deny incoming
            sudo ufw default allow outgoing

            sudo ufw allow in on lo
            sudo ufw allow out on lo
            sudo ufw deny in from 127.0.0.0/8
            sudo ufw deny in from ::1


            if [[ $allowSSH == *y* ]]; then 
                sudo ufw allow ssh; 
                whitelistedServices+=("ssh")
            fi
            if [[ $allowFTP == *y* ]]; then sudo ufw allow ftp; fi

            echo -e "---\nConfiguring ip tables"
            # The following is mostly stolen from https://github.com/dolegi/lockdown.sh/blob/master/lockdown.sh
            # Flush existing rules
            iptables -F

            # Defaults
            iptables -P INPUT DROP
            iptables -P FORWARD DROP
            iptables -P OUTPUT ACCEPT

            # Accept loopback input
            iptables -A INPUT -i lo -p all -j ACCEPT
            
            # Allow three-way Handshake
            iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

            # Stop Masked Attacks
            iptables -A INPUT -p icmp --icmp-type 13 -j DROP
            iptables -A INPUT -p icmp --icmp-type 17 -j DROP
            iptables -A INPUT -p icmp --icmp-type 14 -j DROP
            iptables -A INPUT -p icmp -m limit --limit 1/second -j ACCEPT

            # Discard invalid Packets
            iptables -A INPUT -m state --state INVALID -j DROP
            iptables -A FORWARD -m state --state INVALID -j DROP
            iptables -A OUTPUT -m state --state INVALID -j DROP

            # Drop Spoofing attacks
            iptables -A INPUT -s 10.0.0.0/8 -j DROP
            iptables -A INPUT -s 169.254.0.0/16 -j DROP
            iptables -A INPUT -s 172.16.0.0/12 -j DROP
                iptables -A INPUT -s 127.0.0.0/8 -j DROP
            iptables -A INPUT -s 192.168.0.0/24 -j DROP
            iptables -A INPUT -s 224.0.0.0/4 -j DROP
            iptables -A INPUT -d 224.0.0.0/4 -j DROP
            iptables -A INPUT -s 240.0.0.0/5 -j DROP
            iptables -A INPUT -d 240.0.0.0/5 -j DROP
            iptables -A INPUT -s 0.0.0.0/8 -j DROP
            iptables -A INPUT -d 0.0.0.0/8 -j DROP
            iptables -A INPUT -d 239.255.255.0/24 -j DROP
            iptables -A INPUT -d 255.255.255.255 -j DROP

            # Drop packets with excessive RST to avoid Masked attacks
            iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT

            # Block ips doing portscan for 24 hours
            iptables -A INPUT   -m recent --name portscan --rcheck --seconds 86400 -j DROP
            iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP

            # After 24 hours remove IP from block list
            iptables -A INPUT   -m recent --name portscan --remove
            iptables -A FORWARD -m recent --name portscan --remove

            # Allow ssh
            iptables -A INPUT -p tcp -m tcp --dport 141 -j ACCEPT

            # Allow Ping
            iptables -A INPUT -p icmp --icmp-type 0 -j ACCEPT

            # Allow one ssh connection at a time
            iptables -A INPUT -p tcp --syn --dport 141 -m connlimit --connlimit-above 2 -j REJECT

            iptables-save > /etc/iptables/rules.v4
            ip6tables-save > /etc/iptables/rules.v6

            # enable port scna attack detection
            echo "127.0.0.1    0;" >> "/etc/psad/auto_dl"
            sed -i "s/EMAIL_ADDRESSES             root@localhost;/EMAIL_ADDRESSES             root@localhost;/" "/etc/psad/auto_dl"
            sed -i "s/HOSTNAME                    _CHANGEME_;/HOSTNAME                    $(hostname --fqdn);/" "/etc/psad/auto_dl"
            sed -i 's/ENABLE_AUTO_IDS             N;/ENABLE_AUTO_IDS               Y;/' "/etc/psad/auto_dl"
            sed -i 's/DANGER_LEVEL2               15;/DANGER_LEVEL2               15;/' "/etc/psad/auto_dl"
            sed -i 's/DANGER_LEVEL3               150;/DANGER_LEVEL3               150;/' "/etc/psad/auto_dl"
            sed -i 's/DANGER_LEVEL4               1500;/DANGER_LEVEL4               1500;/' "/etc/psad/auto_dl"
            sed -i 's/DANGER_LEVEL5               10000;/DANGER_LEVEL5               10000;/' "/etc/psad/auto_dl"
            sed -i 's/EMAIL_ALERT_DANGER_LEVEL    1;/EMAIL_ALERT_DANGER_LEVEL    5;/' "/etc/psad/auto_dl"
            sed -i 's/EMAIL_LIMIT                 0;/EMAIL_LIMIT                 5;/' "/etc/psad/auto_dl"
            sed -i 's/EXPECT_TCP_OPTIONS             *;/EXPECT_TCP_OPTIONS             Y;/' "/etc/psad/auto_dl"
            sed -i 's/ENABLE_MAC_ADDR_REPORTING   N;/ENABLE_MAC_ADDR_REPORTING   Y;/' "/etc/psad/auto_dl"
            sed -i 's/AUTO_IDS_DANGER_LEVEL       5;/AUTO_IDS_DANGER_LEVEL       1;/' "/etc/psad/auto_dl"
            sed -i 's/ENABLE_AUTO_IDS_EMAILS      ;/ENABLE_AUTO_IDS_EMAILS      Y;/' "/etc/psad/auto_dl"
            sed -i 's/IGNORE_PORTS             *;/IGNORE_PORTS             NONE;/' "/etc/psad/auto_dl"
            sed -i 's/IPT_SYSLOG_FILE             \/var\/log\/messages;/IPT_SYSLOG_FILE             \/var\/log\/syslog;/' "/etc/psad/auto_dl"
            sed -i 's/SIG_UPDATE_URL              http:\/\/www.cipherdyne.org\/psad\/signatures;/SIG_UPDATE_URL              https:\/\/www.cipherdyne.org\/psad\/signatures;/'  "/etc/psad/auto_dl"

            psad --sig-update 1> /dev/null
            psad -H
            psad --fw-analyze 1> /dev/null
            systemctl start psad
            systemctl enable psad

            # DNS, but I lost my internet when I did it
            # dnslist=""
            # mapfile -t dnsarray < <( grep ^nameserver /etc/resolv.conf | sed 's/^nameserver\s//g' )
            # dnslist=${dnsarray[*]}
            # echo "DNS: $dnslist"
            # if [ ${#dnsarray[@]} -lt 2 ]; then
            #     dnslist="$dnslist 1.1.1.1"
            # fi
            # echo "DNS: $dnslist"
            # sed -i "s/^DNS=.*/DNS=$dnslist/" "/etc/systemd/resolved.conf"
            # sed -i "s/^#DNS=.*/DNS=$dnslist/" "/etc/systemd/resolved.conf"
            # sed -i "s/^FallbackDNS=.*/FallbackDNS=1.0.0.1/" "/etc/systemd/resolved.conf"
            # sed -i "s/^#FallbackDNS=.*/FallbackDNS=1.0.0.1/" "/etc/systemd/resolved.conf"
            sed -i "s/^DNSSEC=.*/DNSSEC=yes/" "/etc/systemd/resolved.conf"
            sed -i "s/^#DNSSEC=.*/DNSSEC=yes/" "/etc/systemd/resolved.conf"
            sed -i "s/^DNSOverTLS=.*/DNSOverTLS=opportunistic/" "/etc/systemd/resolved.conf"
            sed -i "s/^#DNSOverTLS=.*/DNSOverTLS=opportunistic/" "/etc/systemd/resolved.conf"
            # sed -i '/^hosts:/ s/files dns/files resolve dns/' /etc/nsswitch.conf
            systemctl daemon-reload
            # echo "DNS: $dnslist"

            for n in $(arp -n -a | awk '{print $NF}' | sort | uniq); do
                echo "net.ipv6.conf.$n.accept_ra_rtr_pref = 0" >> "/etc/sysctl.conf"
            done
            chmod 0600 /etc/sysctl.conf


            ;;
        8)  # services
            echo -e "---\nRemoving unessesary services"
            sudo apt-get remove samba -y
            services=$(sudo service --status-all)
            activeServices=($(echo $services | grep -Po '(?<=\[\s\+\s\]\s)(\w|-)+'))

            for i in "${activeServices[@]}"
            do
                if ([[ " ${whitelistedServices[*]} " != *" $i "* && -n "$i" ]]) then 
                    echo -e "-\n$i is not whitelisted"
                    read -p "Remove $i service? [y/N]: " removeService
                    if [[ $removeService == *y* ]]; then 
                        sudo systemctl stop $i
                        sudo systemctl disable $i
                        echo "Uninstalling..."
                        sudo apt remove $i -y
                        echo "Purging..."
                        sudo dpkg --purge $i
                    fi;
                fi;
            done

            echo -e "Enable security services"
            echo -e "---\nEnable acct.service\n---"
            sudo systemctl enable acct.service
            sudo systemctl start acct.service

            echo -e "---\nEnable fail2ban\n---"
            cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
            sudo systemctl enable fail2ban
            sudo systemctl start fail2ban
            service fail2ban restart

            echo -e "---\nApparmor\n---"
            if ! grep 'session.*pam_apparmor.so order=user,group,default' /etc/pam.d/*; then
                echo 'session optional pam_apparmor.so order=user,group,default' > /etc/pam.d/apparmor
            fi
            sudo systemctl enable apparmor.service
            sudo systemctl start apparmor.service
            sudo systemctl restart apparmor.service

            # start and enable the update services
            sudo systemctl enable unattended-upgrades
            sudo systemctl start unattended-upgrades
            sudo systemctl enable update-notifier 2> /dev/null
            sudo systemctl start update-notifier 2> /dev/null
            sudo systemctl restart update-notifier 2> /dev/null
            sudo dpkg-reconfigure --priority=low unattended-upgrades

            systemctl mask debug-shell.service
            systemctl stop debug-shell.service
            systemctl daemon-reload

            sudo systemctl start usbguard.service
            sudo systemctl enable usbguard.service

            sudo find /etc/apparmor.d/ -maxdepth 1 -type f -exec aa-enforce {} \;

            sed -i 's/^CRON_DAILY_RUN=.*/CRON_DAILY_RUN="yes"/' "/etc/default/rkhunter"
            ;;
        9)  # firefox
            echo -e "---\nEnabling popup blocker"
            cd /home/$SUDO_USER
            # this command will be recognized for points right away, but resets when firefox is opened
            sed -i '/user_pref("dom.disable_open_during_load", false);/d' "$(echo .mozilla/firefox/*.default)/prefs.js"
            sed -i '/user_pref("dom.disable_open_during_load", false);/d' "$(echo .mozilla/firefox/*.default-esr)/prefs.js"
            cd .mozilla/firefox/*.default/ && echo 'user_pref("dom.disable_open_during_load", true);' >> user.js
            cd .mozilla/firefox/*.default-esr/ && echo 'user_pref("dom.disable_open_during_load", true);' >> user.js
            cd /home/$SUDO_USER
            sed -i '/user_pref("dom.disable_open_during_load", false);/d' "$(echo .mozilla/firefox/*.default-release)/prefs.js" 2> /dev/null
            echo "Close and reopen firefox"
            # this makes firefox add the above setting itself when opened so it doesn't reset
            cd /home/$SUDO_USER
            ;;
        10) # software
            echo -e "Removing unathorized media files\n---"
            sudo find /home -type f \( -name "*.mp3" -o -name "*.ogg" \) | while read -r file; do
                echo "Removing media file found at at $file"
                log "Media files $file"
                rm -f "$file"
            done

            echo -e "---\nRemoving unathorized software"
            for software in "${blacklistedSoftware[@]}"; do
                echo "Removing $software"
                sudo apt purge $software -y
                sudo dpkg --purge $software
            done

            
            ;;
        11) # kernal
            # configure kernal security rules
            echo -e "---\nConfiguring kernal security\n---"
            echo "$LockdownConf80" > /etc/sysctl.d/80-lockdown.conf # make sure there is not another file overriding these rules
            sysctl --system

            # same stuff, another method (in case the scorer onlyl sees one)
            touch /etc/sysctl.d/ccdc.conf
            chown root:root /etc/sysctl.d/ccdc.conf
            chmod 644 /etc/sysctl.d/ccdc.conf
            echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.d/ccdc.conf #Log suspicious packets
            echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.d/ccdc.conf #Ignore ICMP Broadcasts
            echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.d/ccdc.conf #Ignore bogus ICMP responses
            echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.d/ccdc.conf #Enable syn cookies 
            echo "kernel.randomize_va_space = 2" >> /etc/sysctl.d/ccdc.conf #Enable ASLR

            echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.conf
            echo 'kernel.exec-shield = 1' >> /etc/sysctl.conf

            # same stuff, more dirrect
            echo 1 > /proc/sys/kernel/kptr_restrict
            echo 1 > /proc/sys/kernel/dmesg_restrict
            echo 2 > /proc/sys/kernel/perf_event_paranoid
            echo 1 > /proc/sys/kernel/yama/ptrace_scope
            echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
            echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses
            echo 1 > /proc/sys/net/ipv4/tcp_syncookies
            echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter
            echo 1 > /proc/sys/net/ipv4/conf/default/rp_filter
            echo 2 > /proc/sys/kernel/randomize_va_space

            # disable insecure connection types
            echo -e "---\nDisabling insecure connection types\n---"
            echo "install udf /bin/true
            blacklist firewire-core
            blacklist firewire-ohci
            blacklist firewire-sbp2" >> /etc/modprobe.d/blacklist.conf
            echo "blacklist usb-storage" >> /etc/modprobe.d/blacklist.conf

            echo -e "Setting Sticky bit on all world-writable directories"
            sudo df --local -P | awk {'if (NR!=1) print $6'} | sudo xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | sudo xargs chmod a+t

            # disable uncommon protocols
            echo -e "---\nDisabling uncommon protocols\n---"
            echo "install sctp /bin/true
            install dccp /bin/true
            install rds /bin/true
            install tipc /bin/true" >> /etc/modprobe.d/protocols.conf

            # block USBs by default
            echo "deny" | sudo tee -a /etc/usbguard/rules.conf
            systemctl stop udisks.service
            systemctl disable udisks.service

            MOD="bluetooth bnep btusb cpia2 firewire-core floppy n_hdlc net-pf-31 pcspkr soundcore thunderbolt usb-midi usb-storage uvcvideo v4l2_common"
            for disable in $MOD; do
                if ! grep -q "$disable" "/etc/modprobe.d/disablemod.conf" 2> /dev/null; then
                    echo "install $disable /bin/true" >> "/etc/modprobe.d/disablemod.conf"
                fi
            done

            NET="dccp sctp rds tipc"
            for disable in $NET; do
                if ! grep -q "$disable" "/etc/modprobe.d/disablenet.conf" 2> /dev/null; then
                echo "install $disable /bin/true" >> "/etc/modprobe.d/disablenet.conf"
                fi
            done

            
            ;;
        12) # miscellaneous
            echo -e "---\nChecking for SUID files\n---"
            # echo "This should not be nessesary, as the hardening script has already done it with a more extensive list. Keeping this code anyways"
            excluded_programs=("write" "ntfs-3g" "pkexec" "crontab" "exim4" "pppd" "su" "sudo" "passwd" "ping" "mount" "umount" "ssh-keysign" "dbus-daemon-launch-helper" "snap-confine" "Xorg.wrap" "polkit-agent-helper-1" "camel-lock-helper-1.2" "pam-tmpdir-helper" "postdrop" "unix_chkpwd" "postqueue" "pam_extrausers_chkpwd" "vlock-main" "dotlockfile" "expiry" "wall" "chage" "chfn" "chsh" "newgrp" "ssh-agent")
            blacklist_progrmas=("plocate")
            echo "Scanning for suid bit programs..."
            suid_files=$( find / -type f -perm /6000 2>/dev/null | grep -vE "($(IFS="|"; echo "${excluded_programs[*]}"))")
            echo "Scan finished"

            # remove bit from blacklisted files
            for file in $( echo "$suid_files" | grep -E -w -i "$(IFS="|"; echo "${blacklist_progrmas[*]}")" ); do
                echo "Removing SUID bit from $file..."
                sudo chmod u-s,g-s "$file"
            done

            # ask if bit should be removed from unknown files
            for file in $suid_files; do
                read -p "Do you want to remove the SUID bit from $file? (y/n): " choice
                if [ "$choice" = "y" ] || [ "$choice" = "Y" ]; then
                    echo "Removing SUID bit from $file..."
                    sudo chmod u-s,g-s "$file"
                else
                    echo "SUID bit for $file is not removed."
                fi
            done

            # banners
            echo -e "---\nConfiguring banners"
            echo "
            Custom banner just because - Custom banner just because
            " > /etc/issue
            echo "
            Custom banner just because - Custom banner just because
            " > /etc/issue.net

            # This could cause issues, not sure, don't run
            # Set grub password
            echo -e "---\nSetting grub password?"
            if grep -q '^GRUB_PASSWORD=' /etc/default/grub; then
                echo "A GRUB password is already set."
            else
                grubpass=$(echo -e "$newPassword\n$newPassword" | LC_ALL=C grub-mkpasswd-pbkdf2 | awk '/hash of / {print $NF}')
                echo "GRUB_ENABLE_CRYPTODISK=y" | sudo tee -a /etc/default/grub
                echo "GRUB_PASSWORD=$grubpass" | sudo tee -a /etc/default/grub
                echo "GRUB password set."
                
                # insert pass to saved file, save file as grub config
                grubConfigWithPass=$(echo "$grubConfig" | awk -v grubpass="$grubpass" '{gsub(/<grubpass>/, grubpass)}1')
                echo "$grubConfigWithPass" | sudo tee -a /etc/grub.d/00_header

                sudo update-grub
            fi

            echo "Disabling USB devices"
            echo 'install usb-storage /bin/true' >> /etc/modprobe.d/disable-usb-storage.conf

            echo "Removing old communication schemes"
            sudo apt --purge remove xinetd nis yp-tools tftpd atftpd tftpd-hpa telnetd rsh-server rsh-redone-server

            echo "Enabling SELinux"
            setenforce 1
            getenforce

            echo "Limiting weak passwords"
            echo 'password sufficient pam_unix.so use_authtok md5 shadow remember=12' >> /etc/pam.d/common-password
            echo 'password sufficient pam_unix.so use_authtok md5 shadow remember=12' >> /etc/pam.d/system-auth
            echo 'password required pam_cracklib.so retry=3 minlen=10 difok=6' >> /etc/pam.d/system-auth

            # Restrict compilers ig?
            ASCOMP="$(command -v as)"
            if [ -f "$ASCOMP" ] && [ -x "$ASCOMP" ]; then
                chmod 0750 "$(readlink -eq $(command -v as))"
            fi
            echo

            # Some cron stuff
            rm /etc/cron.deny 2> /dev/null
            rm /etc/at.deny 2> /dev/null
            echo 'root' > /etc/cron.allow
            echo 'root' > /etc/at.allow
            chown root:root /etc/cron*
            chmod og-rwx /etc/cron*
            chown root:root /etc/at*
            chmod og-rwx /etc/at*
            echo ALL >> /etc/cron.deny
            systemctl mask atd.service
            systemctl stop atd.service
            systemctl daemon-reload

            # @BLOCK
            echo "sshd : ALL : ALLOW" > /etc/hosts.allow
            echo "ALL: LOCAL, 127.0.0.1" >> /etc/hosts.allow
            echo "ALL: ALL" > /etc/hosts.deny
            chmod 644 /etc/hosts.allow
            chmod 644 /etc/hosts.deny

            for f in /etc/issue /etc/issue.net /etc/motd; do
                TEXT="\\nBy accessing this system, you consent to the following conditions:
            - This system is for authorized use only.
            - Any or all uses of this system and all files on this system may be monitored.
            - Communications using, or data stored on, this system are not private.
            "
                echo -e "$TEXT" > $f
            done

            sed -i 's/^#Storage=.*/Storage=persistent/' "/etc/systemd/journald.conf"
            sed -i 's/^#ForwardToSyslog=.*/ForwardToSyslog=yes/' "/etc/systemd/journald.conf"
            sed -i 's/^#Compress=.*/Compress=yes/' "/etc/systemd/journald.conf"
            systemctl restart systemd-journald
            if [ -w "/etc/rsyslog.conf" ]; then
                sed -i "s/^\$FileCreateMode.*/\$FileCreateMode 0600/g" "/etc/rsyslog.conf"
            fi

            if test -f /etc/default/motd-news; then
                sed -i 's/ENABLED=.*/ENABLED=0/' /etc/default/motd-news
                systemctl stop motd-news.timer
                systemctl mask motd-news.timer
                if command -v pro 2>/dev/null 1>&2; then
                    pro config set apt_news=false
                fi
            fi
            chmod -x /etc/update-motd.d/*
            rm /var/run/motd.dynamic

            echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections
            echo "postfix postfix/mailname string $(hostname -f)" | debconf-set-selections

            # Path stuff
            sed -i 's/PATH=.*/PATH=\"\/usr\/local\/bin:\/usr\/sbin:\/usr\/bin:\/bin:\/snap\/bin"/' /etc/environment
            echo "$initpath" > /etc/profile.d/initpath.sh
            chown root:root /etc/profile.d/initpath.sh
            chmod 0644 /etc/profile.d/initpath.sh

            postconf -e disable_vrfy_command=yes 2> /dev/null
            postconf -e smtpd_banner="\$myhostname ESMTP" 2> /dev/null
            postconf -e smtpd_client_restrictions=permit_mynetworks,reject 2> /dev/null
            postconf -e inet_interfaces=loopback-only 2> /dev/null
            systemctl restart postfix.service 2> /dev/null

            update-grub 2> /dev/null

            if ! grep -E '^\+\s:\sroot\s:\s127.0.0.1$|^:root:127.0.0.1' "/etc/security/access.conf"; then
                sed -i 's/^#.*root.*:.*127.0.0.1$/+:root:127.0.0.1/' "/etc/security/access.conf"
            fi
            echo "console" > /etc/securetty

            if ! grep -qER '^Defaults.*use_pty$' /etc/sudo*; then
                echo "Defaults use_pty" > /etc/sudoers.d/011_use_pty
            fi
            if ! grep -qER '^Defaults.*logfile' /etc/sudo*; then
                echo 'Defaults logfile="/var/log/sudo.log"' > /etc/sudoers.d/012_logfile
            fi
            if ! grep -qER '^Defaults.*pwfeedback' /etc/sudo*; then
                echo 'Defaults !pwfeedback' > /etc/sudoers.d/013_pwfeedback
            fi
            if ! grep -qER '^Defaults.*visiblepw' /etc/sudo*; then
                echo 'Defaults !visiblepw' > /etc/sudoers.d/014_visiblepw
            fi
            if ! grep -qER '^Defaults.*passwd_timeout' /etc/sudo*; then
                echo 'Defaults passwd_timeout=1' > /etc/sudoers.d/015_passwdtimeout
            fi
            if ! grep -qER '^Defaults.*timestamp_timeout' /etc/sudo*; then
                echo 'Defaults timestamp_timeout=5' > /etc/sudoers.d/016_timestamptimeout
            fi
            find /etc/sudoers.d/ -type f -name '[0-9]*' -exec chmod 0440 {} \;
            if ! grep -qER '^auth required pam_wheel.so' /etc/pam.d/su; then
                echo "auth required pam_wheel.so use_uid group=sudo" >> /etc/pam.d/su
            fi


            sed -i 's/^#DumpCore=.*/DumpCore=no/' "/etc/systemd/system.conf"
            sed -i 's/^#CrashShell=.*/CrashShell=no/' "/etc/systemd/system.conf"
            sed -i 's/^#DefaultLimitCORE=.*/DefaultLimitCORE=0/' "/etc/systemd/system.conf"
            sed -i 's/^#DefaultLimitNOFILE=.*/DefaultLimitNOFILE=1024/' "/etc/systemd/system.conf"
            sed -i 's/^#DefaultLimitNPROC=.*/DefaultLimitNPROC=1024/' "/etc/systemd/system.conf"
            sed -i 's/^#DefaultLimitCORE=.*/DefaultLimitCORE=0/' "/etc/systemd/user.conf"
            sed -i 's/^#DefaultLimitNOFILE=.*/DefaultLimitNOFILE=1024/' "/etc/systemd/user.conf"
            sed -i 's/^#DefaultLimitNPROC=.*/DefaultLimitNPROC=1024/' "/etc/systemd/user.conf"

            echo 'hard core 0' >> /etc/security/limits.conf
            echo 'fs.suid_dumpable = 0' >> /etc/sysctl.conf
            echo 'ulimit -S -c 0 > /dev/null 2>&1' >> /etc/profile



            for users in games gnats irc list news sync uucp; do
                userdel -r "$users" 2> /dev/null
            done

            ;;
        
        13) # ssh
            echo -e "---\nSecuring ssh\n---"
            echo "
            AllowTcpForwarding no
            ClientAliveCountMax 2
            ClientAliveInterval 300
            Compression no
            MaxSessions 2
            AllowAgentForwarding no
            Port 141
            Protocol 2
            HostKey /etc/ssh/ssh_host_rsa_key
            HostKey /etc/ssh/ssh_host_dsa_key
            HostKey /etc/ssh/ssh_host_ecdsa_key
            KeyRegenerationInterval 3600
            ServerKeyBits 768
            SyslogFacility AUTH
            LogLevel VERBOSE
            LoginGraceTime 60
            PermitRootLogin no
            StrictModes yes
            RSAAuthentication yes
            PubkeyAuthentication yes
            IgnoreRhosts yes
            RhostsRSAAuthentication no
            HostbasedAuthentication no
            PermitUserEnvironment no
            PermitEmptyPasswords no
            ChallengeResponseAuthentication no
            PasswordAuthentication no
            # Kerberos options
            #KerberosAuthentication no
            #KerberosGetAFSToken no
            #KerberosOrLocalPasswd yes
            #KerberosTicketCleanup yes
            # GSSAPI options
            #GSSAPIAuthentication no
            #GSSAPICleanupCredentials yes
            X11Forwarding no
            X11DisplayOffset 10
            PrintMotd no
            PrintLastLog yes
            TCPKeepAlive no
            MaxAuthTries 3
            AcceptEnv LANG LC_*
            Subsystem sftp /usr/lib/openssh/sftp-server
            UsePAM yes
            maxstartups 10:30:60
            KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
            " > /etc/ssh/sshd_config
            echo "ALL : ALL" >> /etc/hosts.deny
            echo "sshd : localhost" > /etc/hosts.allow

            
            read -p "Wait for ssh points, log them, then press enter to use konstruktoid/hardening method: "


            awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.tmp
            mv /etc/ssh/moduli.tmp /etc/ssh/moduli

            if grep -q '^Include' /etc/ssh/sshd_config; then
                local INCLUDEDIR
                # shellcheck disable=SC2046
                INCLUDEDIR="$(dirname $(grep '^Include' /etc/ssh/sshd_config | awk '{print $NF}'))"

                if [ ! -d "$INCLUDEDIR" ]; then
                mkdir -p "$INCLUDEDIR"
                fi
                SSHDCONF="$INCLUDEDIR/hardening.conf"
                cp "/etc/ssh/sshd_config" "$SSHDCONF"
                sed -i '/.*Subsystem.*/d' "/etc/ssh/sshd_config"
                sed -i '/Include.*/d' "$SSHDCONF"
            else
                SSHDCONF="/etc/ssh/sshd_config"
            fi

            sed -i '/HostKey.*ssh_host_dsa_key.*/d' "$SSHDCONF"
            sed -i '/KeyRegenerationInterval.*/d' "$SSHDCONF"
            sed -i '/ServerKeyBits.*/d' "$SSHDCONF"
            sed -i '/UseLogin.*/d' "$SSHDCONF"

            sed -i 's/.*X11Forwarding.*/X11Forwarding no/' "$SSHDCONF"
            sed -i 's/.*LoginGraceTime.*/LoginGraceTime 20/' "$SSHDCONF"
            sed -i 's/.*PermitRootLogin.*/PermitRootLogin no/' "$SSHDCONF"
            sed -i 's/.*UsePrivilegeSeparation.*/UsePrivilegeSeparation sandbox/' "$SSHDCONF"
            sed -i 's/.*LogLevel.*/LogLevel VERBOSE/' "$SSHDCONF"
            sed -i 's/.*Banner.*/Banner \/etc\/issue.net/' "$SSHDCONF"
            sed -i 's/.*Subsystem.*sftp.*/Subsystem sftp internal-sftp/' "$SSHDCONF"
            sed -i 's/^#.*Compression.*/Compression no/' "$SSHDCONF"
            sed -i "s/.*Port.*/Port $SSH_PORT/" "$SSHDCONF"

            echo "" >> "$SSHDCONF"

            if ! grep -q "^LogLevel" "$SSHDCONF" 2> /dev/null; then
                echo "LogLevel VERBOSE" >> "$SSHDCONF"
            fi

            if ! grep -q "^PrintLastLog" "$SSHDCONF" 2> /dev/null; then
                echo "PrintLastLog yes" >> "$SSHDCONF"
            fi

            if ! grep -q "^IgnoreUserKnownHosts" "$SSHDCONF" 2> /dev/null; then
                echo "IgnoreUserKnownHosts yes" >> "$SSHDCONF"
            fi

            if ! grep -q "^PermitEmptyPasswords" "$SSHDCONF" 2> /dev/null; then
                echo "PermitEmptyPasswords no" >> "$SSHDCONF"
            fi

            if ! grep -q "^AllowGroups" "$SSHDCONF" 2> /dev/null; then
                echo "AllowGroups $SSH_GRPS" >> "$SSHDCONF"
            fi

            if ! grep -q "^MaxAuthTries" "$SSHDCONF" 2> /dev/null; then
                echo "MaxAuthTries 3" >> "$SSHDCONF"
            else
                sed -i 's/MaxAuthTries.*/MaxAuthTries 3/' "$SSHDCONF"
            fi

            if ! grep -q "^ClientAliveInterval" "$SSHDCONF" 2> /dev/null; then
                echo "ClientAliveInterval 200" >> "$SSHDCONF"
            fi

            if ! grep -q "^ClientAliveCountMax" "$SSHDCONF" 2> /dev/null; then
                echo "ClientAliveCountMax 3" >> "$SSHDCONF"
            fi

            if ! grep -q "^PermitUserEnvironment" "$SSHDCONF" 2> /dev/null; then
                echo "PermitUserEnvironment no" >> "$SSHDCONF"
            fi

            if ! grep -q "^KexAlgorithms" "$SSHDCONF" 2> /dev/null; then
                echo 'KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256' >> "$SSHDCONF"
            fi

            if ! grep -q "^Ciphers" "$SSHDCONF" 2> /dev/null; then
                echo 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr' >> "$SSHDCONF"
            fi

            if ! grep -q "^Macs" "$SSHDCONF" 2> /dev/null; then
                echo 'Macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256' >> "$SSHDCONF"
            fi

            if ! grep -q "^MaxSessions" "$SSHDCONF" 2> /dev/null; then
                echo "MaxSessions 3" >> "$SSHDCONF"
            else
                sed -i 's/MaxSessions.*/MaxSessions 3/' "$SSHDCONF"
            fi

            if ! grep -q "^UseDNS" "$SSHDCONF" 2> /dev/null; then
                echo "UseDNS no" >> "$SSHDCONF"
            else
                sed -i 's/UseDNS.*/UseDNS no/' "$SSHDCONF"
            fi

            if ! grep -q "^StrictModes" "$SSHDCONF" 2> /dev/null; then
                echo "StrictModes yes" >> "$SSHDCONF"
            else
                sed -i 's/StrictModes.*/StrictModes yes/' "$SSHDCONF"
            fi

            if ! grep -q "^MaxStartups" "$SSHDCONF" 2> /dev/null; then
                echo "MaxStartups 10:30:60" >> "$SSHDCONF"
            else
                sed -i 's/MaxStartups.*/MaxStartups 10:30:60/' "$SSHDCONF"
            fi

            if ! grep -q "^HostbasedAuthentication" "$SSHDCONF" 2> /dev/null; then
                echo "HostbasedAuthentication no" >> "$SSHDCONF"
            else
                sed -i 's/HostbasedAuthentication.*/HostbasedAuthentication no/' "$SSHDCONF"
            fi

            if ! grep -q "^KerberosAuthentication" "$SSHDCONF" 2> /dev/null; then
                echo "KerberosAuthentication no" >> "$SSHDCONF"
            else
                sed -i 's/KerberosAuthentication.*/KerberosAuthentication no/' "$SSHDCONF"
            fi

            if ! grep -q "^GSSAPIAuthentication" "$SSHDCONF" 2> /dev/null; then
                echo "GSSAPIAuthentication no" >> "$SSHDCONF"
            else
                sed -i 's/GSSAPIAuthentication.*/GSSAPIAuthentication no/' "$SSHDCONF"
            fi

            if ! grep -q "^RekeyLimit" "$SSHDCONF" 2> /dev/null; then
                echo "RekeyLimit 512M 1h" >> "$SSHDCONF"
            else
                sed -i 's/RekeyLimit.*/RekeyLimit 512M 1h/' "$SSHDCONF"
            fi

            if ! grep -q "^AllowTcpForwarding" "$SSHDCONF" 2> /dev/null; then
                echo "AllowTcpForwarding no" >> "$SSHDCONF"
            else
                sed -i 's/AllowTcpForwarding.*/AllowTcpForwarding no/' "$SSHDCONF"
            fi

            if ! grep -q "^AllowAgentForwarding" "$SSHDCONF" 2> /dev/null; then
                echo "AllowAgentForwarding no" >> "$SSHDCONF"
            else
                sed -i 's/AllowAgentForwarding.*/AllowTcpForwarding no/' "$SSHDCONF"
            fi

            if ! grep -q "^TCPKeepAlive" "$SSHDCONF" 2> /dev/null; then
                echo "TCPKeepAlive no" >> "$SSHDCONF"
            else
                sed -i 's/TCPKeepAlive.*/TCPKeepAlive no/' "$SSHDCONF"
            fi

            cp "$SSHDCONF" "/etc/ssh/sshd_config.$(date +%y%m%d)"
            grep -vE '#|^$' "/etc/ssh/sshd_config.$(date +%y%m%d)" | sort | uniq > "$SSHDCONF"
            rm "/etc/ssh/sshd_config.$(date +%y%m%d)"

            chown root:root "$SSHDCONF"
            chmod 0600 "$SSHDCONF"

            cp "/etc/ssh/ssh_config" "/etc/ssh/ssh_config.$(date +%y%m%d)"

            if ! grep -q "^\s.*HashKnownHosts" "/etc/ssh/ssh_config" 2> /dev/null; then
                sed -i '/HashKnownHosts/d' "/etc/ssh/ssh_config"
                echo "    HashKnownHosts yes" >> "/etc/ssh/ssh_config"
            fi
            sed -i 's/#.*Ciphers .*/    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr/g' "/etc/ssh/ssh_config"
            sed -i 's/#.*MACs .*/    MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256/' "/etc/ssh/ssh_config"


            sudo systemctl restart sshd
            ;;
        
        14) # filesystem
            # Disable uncommon filesystems
            echo -e "---\nDisabling uncommon filesystems\n---"
            echo "install cramfs /bin/true
            install freevxfs /bin/true
            install hfs /bin/true
            install hfsplus /bin/true
            install jffs2 /bin/true
            install squashfs /bin/true
            install udf /bin/true
            install vfat /bin/true" >> /etc/modprobe.d/filesystems.conf

            echo -e "Setting Sticky bit on all world-writable directories"
            sudo df --local -P | awk {'if (NR!=1) print $6'} | sudo xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | sudo xargs chmod a+t

            # file access
            echo -e "---\nChanging perms on dirrectories\n---"
            chmod 700 /root
            chmod o-rx /usr/bin/as # compilers

            echo -e "---\nSecuring tmp folder\n---"
            echo "tmpfs /tmp tmpfs rw,nosuid,nodev" >> /etc/fstab # TODO: What's the point?

            modify_fstab_entry() {
                local filesystem="$1"
                local options="$2"

                if grep -q "$filesystem" /etc/fstab; then
                    sed -i "s|^\($filesystem .*\)$|\\1,$options|" /etc/fstab
                else
                    echo "$filesystem $options" >> /etc/fstab
                fi

                echo "Updated /etc/fstab entry for $filesystem with options: $options"
            }
            cp /etc/fstab /etc/fstab.bak

            modify_fstab_entry "/boot" "ro,noexec"
            modify_fstab_entry "/tmp" "noexec,nodev"

            # configure mount permissions - NOTE: dev needs dev perms,
            echo -e "---\nRemounting filesystem with seecure params\n---"
            mount -o remount,noexec /tmp
            mount -o remount,rw,hidepid=2 /proc
            mount -o remount,noexec /dev
            mount -o remount,nodev /run
            mount -o remount,noexec,ro /boot

            # changes=(
            #     "none /tmp tmpfs rw,noexec 0 0"
            #     "none /proc proc rw,hidepid=2 0 0"
            #     "none /dev tmpfs rw,noexec 0 0"
            #     "none /run tmpfs rw,nodev 0 0"
            # )
            # for change in "${changes[@]}"; do
            #     if grep -q "$change" /etc/fstab; then
            #         echo "Entry '$change' already exists in /etc/fstab. Skipping..."
            #     else
            #         echo "$change" >> /etc/fstab
            #         echo "Added entry: '$change'"
            #     fi
            # done

            # Set fstab from konstruktoid/hardening
            cp ./config/tmp.mount /etc/systemd/system/tmp.mount
            cp /etc/fstab /etc/fstab.bck
            TMPFSTAB=$(mktemp --tmpdir fstab.XXXXX)

            sed -i '/floppy/d' /etc/fstab
            grep -v -E '[[:space:]]/boot[[:space:]]|[[:space:]]/home[[:space:]]|[[:space:]]/var/log[[:space:]]|[[:space:]]/var/log/audit[[:space:]]|[[:space:]]/var/tmp[[:space:]]' /etc/fstab > "$TMPFSTAB"
            if grep -q '[[:space:]]/boot[[:space:]].*' /etc/fstab; then
                grep '[[:space:]]/boot[[:space:]].*' /etc/fstab | sed 's/defaults/defaults,nosuid,nodev/g' >> "$TMPFSTAB"
            fi
            if grep -q '[[:space:]]/home[[:space:]].*' /etc/fstab; then
                grep '[[:space:]]/home[[:space:]].*' /etc/fstab | sed 's/defaults/defaults,nosuid,nodev/g' >> "$TMPFSTAB"
            fi
            if grep -q '[[:space:]]/var/log[[:space:]].*' /etc/fstab; then
                grep '[[:space:]]/var/log[[:space:]].*' /etc/fstab | sed 's/defaults/defaults,nosuid,nodev,noexec/g' >> "$TMPFSTAB"
            fi
            if grep -q '[[:space:]]/var/log/audit[[:space:]].*' /etc/fstab; then
                grep '[[:space:]]/var/log/audit[[:space:]].*' /etc/fstab | sed 's/defaults/defaults,nosuid,nodev,noexec/g' >> "$TMPFSTAB"
            fi
            if grep -q '[[:space:]]/var/tmp[[:space:]].*' /etc/fstab; then
                grep '[[:space:]]/var/tmp[[:space:]].*' /etc/fstab | sed 's/defaults/defaults,nosuid,nodev,noexec/g' >> "$TMPFSTAB"
            fi
            cp "$TMPFSTAB" /etc/fstab
            if ! grep -q '/run/shm ' /etc/fstab; then
                echo 'none /run/shm tmpfs rw,noexec,nosuid,nodev 0 0' >> /etc/fstab
            fi
            if ! grep -q '/dev/shm ' /etc/fstab; then
                echo 'none /dev/shm tmpfs rw,noexec,nosuid,nodev 0 0' >> /etc/fstab
            fi
            if ! grep -q '/proc ' /etc/fstab; then
                echo 'none /proc proc rw,nosuid,nodev,noexec,relatime,hidepid=2 0 0' >> /etc/fstab
            fi
            if [ -e /etc/systemd/system/tmp.mount ]; then
                sed -i '/^\/tmp/d' /etc/fstab
                for t in $(mount | grep "[[:space:]]/tmp[[:space:]]" | awk '{print $3}'); do
                    umount "$t"
                done
                sed -i '/[[:space:]]\/tmp[[:space:]]/d' /etc/fstab
                ln -s /etc/systemd/system/tmp.mount /etc/systemd/system/default.target.wants/tmp.mount
                sed -i 's/Options=.*/Options=mode=1777,strictatime,noexec,nodev,nosuid/' /etc/systemd/system/tmp.mount
                chmod 0644 /etc/systemd/system/tmp.mount
                systemctl daemon-reload
            else
                echo '/etc/systemd/system/tmp.mount was not found.'
            fi



            # verify file permissions
            echo -e "---\nSecuring user home ownership\n---"
            cd /home
            for username in $allUsers; do
                if [ "$username" != "nobody" ]; then
                    sudo chown -R $username $username
                fi
            done

            for user_dir in /home/*; do
                if [ -d "$user_dir" ]; then
                    # Ensure user home directory permissions
                    sudo chmod 700 "$user_dir"

                    # Set the same permissions recursively for all subdirectories and files
                    sudo find "$user_dir" -type d -exec sudo chmod 700 {} \;
                    sudo find "$user_dir" -type f -exec sudo chmod 700 {} \;
                    echo "Secured $user_dir"
                fi
            done


            echo -e "---\nVerify common root file perms\n---"
            chown root:root /etc/motd
            chmod u-x,go-wx /etc/motd 
            chown root:root /etc/group
            chown root:shadow /etc/gshadow
            chown root:root /etc/passwd
            chown root:shadow /etc/shadow
            chown root:root /etc/passwd-
            chown root:shadow /etc/gshadow-
            chown root:root /etc/group-
            chown root:shadow /etc/shadow-
            chmod 644 /etc/group
            chmod 644 /etc/passwd
            chmod o-rwx,g-wx /etc/gshadow
            chmod o-rwx,g-wx /etc/shadow
            chmod 644 /etc/group-
            chmod 644 /etc/passwd-
            chmod o-rwx,g-wx /etc/gshadow-
            chmod o-rwx,g-wx /etc/shadow-
            systemctl --now disable rsync
            sudo chmod 750 /etc/sudoers.d # these are for lynis warning
            sudo chown root:root /etc/sudoers.d
            sudo chmod 700 /home/* # further secure user homes
            sudo chmod 600 /etc/cups/cupsd.conf # secure cups conf
            sudo chmod 600 /etc/ssh/sshd_config # secure ssh conf

            echo -e "---\nChanging cron file perms\n---"
            echo -e "---\nConfiguring cron\n---"
            systemctl --now enable cron
            chown root:root /etc/crontab
            chown root:root /etc/cron.hourly
            chown root:root /etc/cron.daily
            chown root:root /etc/cron.weekly
            chown root:root /etc/cron.monthly
            chmod og-rwx /etc/crontab
            chmod og-rwx /etc/cron.hourly
            chmod og-rwx /etc/cron.daily
            chmod og-rwx /etc/cron.weekly
            chmod og-rwx /etc/cron.monthly

            FS="cramfs freevxfs jffs2 ksmbd hfs hfsplus udf"
            for disable in $FS; do
                if ! grep -q "$disable" "/etc/modprobe.d/disablefs.conf" 2> /dev/null; then
                    echo "install $disable /bin/true" >> "/etc/modprobe.d/disablefs.conf"
                fi
            done

            ;;
        15) # FTP
            groupadd nogroup
            useradd --home-dir /home/vsftpd --gid nogroup -m --shell /bin/false ftpuser
            if command -v vsftpd &>/dev/null; then
                echo "vsftpd is installed"
                systemctl enable vsftpd
                systemctl start vsftpd
                # find ftp config
                ftpconfig=""
                file_locations=(
                    "/etc/vsftpd.conf"
                    "/etc/vsftpd/vsftpd.conf"
                )
                for location in "${file_locations[@]}"; do
                if [ -e "$location" ]; then
                    ftpconfig=$location
                    break
                fi
                done
                echo "Config file at $ftpconfig"

                mkdir /etc/vsftpd
                cd /etc/vsftpd
                openssl req -x509 -nodes -days 1825 -newkey rsa:2048 -keyout /etc/vsftpd/vsftpd.key -out /etc/vsftpd/vsftpd.pem -subj "/CN=YourCommonName"

                # Create virtual group
                echo "$SUDO_USER" > vusers.txt
                db_load -T -t hash -f vusers.txt vsftpd-virtual-user.db
                chmod 600 vsftpd-virtual-user.db
                rm vusers.txt

                # Configure PAM
                mkdir /root/backup_vsftpd_pam
                cp /etc/pam.d/vsftpd /root/backup_vsftpd_pam/

                mkdir /var/run/vsftpd/empty
                chown ftpuser.nogroup /var/run/vsftpd/empty

                mkdir /etc/vsftpd/vsftpd_user_conf
                echo "local_root=/var/run/vsftpd/empty" | tee /etc/vsftpd/vsftpd_user_conf/ftpuser

                echo "$vsftpConfig" | sudo tee /etc/pam.d/vsftpd

                echo "$ftpConfig" | sudo tee $ftpconfig

                systemctl restart vsftpd

            elif command -v proftpd &>/dev/null; then
                echo "proftpd is installed..."
                # proftpd
                # sudo sed -i 's/^RootLogin on/RootLogin off/' /etc/proftpd/proftpd.conf

                mkdir /etc/proftpd/disabled_mod/
                mkdir /etc/proftpd/enabled_mod/

                echo "$tlsConfig" | tee /etc/proftpd/disabled_mod/tls.conf

                ln -s /etc/proftpd/disabled_mod/tls.conf  /etc/proftpd/enabled_mod/ # link config with mod security

                echo "$proftpConfig" | tee /etc/proftpd/proftpd.conf

                openssl req -x509 -nodes -days 1825 -newkey rsa:2048 -keyout /etc/ssl/private/proftpd.key -out /etc/ssl/certs/proftpd.crt -subj "/CN=YourCommonName"
                chmod 0600 /etc/ssl/private/proftpd.key
                chmod 0600 /etc/ssl/certs/proftpd.crt


                systemctl restart proftpd
            else
                echo "ERROR: No FTP service found. Figure out what is running FTP and how to secure it"
            fi

            ;;
        16) # Webservesr
            read -p "Is this computer running apache? [y/N]: " -r
            if [[ $REPLY =~ ^[Yy]$ ]]
            then
                installAll "libapache2-mod-security2 apache2"
                cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
                sed -i 's/^SecRuleEngine .*/SecRuleEngine On/' /etc/modsecurity/modsecurity.confs

                sudo dpkg -r apache2
                sudo dpkg -P apache2
                sudo apt-get install apache2

                # self-sign:
                sudo openssl req -new -newkey rsa:2048 -days 7 -nodes -x509 \
                    -subj "/C=US/ST=fakeState/L=faceCity/CN=$IP" \
                    -keyout /etc/ssl/private/apache-selfsigned.key \
                    -out /etc/ssl/certs/apache-selfsigned.crt 

                sudo touch /etc/apache2/conf-available/ssl-params.conf
                #Place the following text into ssl-params.conf, read other comments for purpose
                echo "$sslParams" > /etc/apache2/conf-available/ssl-params.conf

                sudo cp /etc/apache2/sites-available/default-ssl.conf /etc/apache2/sites-available/default-ssl.conf.bak
                echo "$defaultSSL" > /etc/apache2/sites-available/default-ssl.conf

                #Force HTTP to redirect to HTTPS
                sed -i "/<VirtualHost \*:80>/a Redirect permanent / https://$IP" \
                /etc/apache2/sites-available/000-default.conf

                # start the apache2 stuff
                sudo a2enmod ssl
                sudo a2enmod headers
                sudo a2ensite default-ssl
                sudo a2enconf ssl-params
                sudo apache2ctl configtest
                sudo systemctl restart apache2
            fi

            # harden nginx 
            read -p "Is this computer running nginx? [y/N]: " -r
            if [[ $REPLY =~ ^[Yy]$ ]]
            then
                # Highly complicated to do myself
                # git clone https://github.com/dev-sec/nginx-baseline
                # sudo apt-get -y install ruby ruby-dev gcc g++ make
                # gem install inspec-bin
                # inspec exec nginx-baseline

                cp /etc/nginx/sites-enabled/default /etc/backups/default.bak # cp /etc/backups/default.bak /etc/nginx/sites-enabled/default
                cp /etc/nginx/nginx.conf /etc/backups/nginx.conf.bak # cp /etc/backups/nginx.conf.bak /etc/nginx/nginx.conf
                
                sed -i "s/ssl_prefer_server_ciphers on;/ssl_prefer_server_ciphers on;\nssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;/" /etc/nginx/nginx.conf
                sed -i "s/ssl_prefer_server_ciphers on;/ssl_prefer_server_ciphers on;\nssl_session_timeout 5m;/" /etc/nginx/nginx.conf
                sed -i "s/ssl_session_timeout 5m;/ssl_session_cache shared:SSL:10m;\nssl_session_timeout 5m;/" /etc/nginx/nginx.conf
                sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header X-Frame-Options DENY;|" /etc/nginx/sites-available/default
                sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header X-XSS-Protection \"1; mode=block\";|" /etc/nginx/sites-available/default
                sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubdomains;\";|" /etc/nginx/sites-available/default
                sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header X-Content-Type-Options nosniff;|" /etc/nginx/sites-available/default
                sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header Content-Security-Policy \"default-src 'self';\";|" /etc/nginx/sites-available/default
                sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header X-Robots-Tag none;|" /etc/nginx/sites-available/default
                sed -i "s/# server_tokens off;/server_tokens off;/g" /etc/nginx/nginx.conf
                sed -i 's/server_tokens off;/server_tokens off;\netag off;/' /etc/nginx/nginx.conf

                echo "The nginx harden is not very thoughrough, please lookup tutorials and continue hardening yourself"
                sleep 2

                systemctl restart nginx
            fi

            ;;
        
        17.1) # Install gnome extensions
            install_aval_package "gnome-shell-extension-manager gnome-tweaks gnome-shell-extensions gnome-shell-extension-panel-osd gnome-shell-extension-dashtodock gnome-shell-extension-desktop-icons-ng"
            # sudo apt install gnome-shell-extension-manager gnome-tweaks gnome-shell-extensions gnome-shell-extension-panel-osd gnome-shell-extension-dashtodock gnome-shell-extension-desktop-icons-ng -y

            ;;
        17.2) # Apply gnome extensions
            gsettings set org.gnome.shell disable-user-extensions false

            # gnome-extensions enable ubuntu-appindicators@ubuntu.com
            gnome-extensions enable panel-osd@berend.de.schouwer.gmail.com
            # gnome-extensions enable user-theme@gnome-shell-extensions.gcampax.github.com
            gnome-extensions enable dash-to-dock@micxgx.gmail.com
            gnome-extensions enable ding@rastersoft.com



            gsettings set org.gnome.shell.extensions.dash-to-dock autohide-in-fullscreen false
            gsettings set org.gnome.shell.extensions.dash-to-dock background-opacity 0.64000000000000001
            gsettings set org.gnome.shell.extensions.dash-to-dock click-action 'focus-or-previews'
            gsettings set org.gnome.shell.extensions.dash-to-dock custom-theme-shrink true
            gsettings set org.gnome.shell.extensions.dash-to-dock dash-max-icon-size 42
            gsettings set org.gnome.shell.extensions.dash-to-dock dock-fixed true
            gsettings set org.gnome.shell.extensions.dash-to-dock dock-position 'LEFT'
            gsettings set org.gnome.shell.extensions.dash-to-dock extend-height true
            gsettings set org.gnome.shell.extensions.dash-to-dock show-apps-at-top true
            gsettings set org.gnome.shell.extensions.dash-to-dock transparency-mode 'FIXED'
            gsettings set org.gnome.shell.extensions.dash-to-dock running-indicator-style 'DOTS'
            gsettings set org.gnome.shell.extensions.dash-to-dock icon-size-fixed true

            gsettings set org.gnome.desktop.background show-desktop-icons true
            gsettings set org.gnome.desktop.wm.preferences button-layout 'close,minimize,maximize:appmenu'
            gsettings set org.gnome.desktop.interface enable-hot-corners true
            gsettings set org.gnome.desktop.interface font-antialiasing 'grayscale'
            gsettings set org.gnome.desktop.interface font-hinting 'slight'
            ;;
        18)

            ;;
        19) 
            ;;
        
        98) # lynis
            echo -e "---\nAuditing system with lynis... (this is not nessesary but will scan for random misconfigurations - you may need to fix them)\n---"
            sleep 3
            sudo apt install git -y # not sure why it is sometimes uninstalled
            git clone https://github.com/CISOfy/lynis
            sudo chown -R 0:0 lynis
            cd lynis
            cp default.prf custom.prf
            echo "skip-test=PLGN-3814" >> custom.prf # Skip test PLGN-3814, it gets stuck and never laods ("Verify journal integrity" test)
            sudo ./lynis audit system --verbose
            ;;

        99) # pre-exit
            sudo apt update
            sudo apt autoremove -y
            sudo apt purge -y
            read -p "Update now? (Could take a while, but most likely say yes) [y/N]: " updateNow
            if [[ $updateNow == *y* ]]; then sudo apt upgrade -y; fi
            sudo apt purge -y $(dpkg -l | grep '^rc' | awk '{print $2}')
            sudo apt autoremove -y
            sudo apt clean

            # reenable scanning apt packages since we are now d
            sed -i 's/^APT_AUTOGEN=.*/APT_AUTOGEN="yes"/' "$RKHUNTERCONF"
            sudo rkhunter --propupd
            ;;
        exit)
            onExit
            exit
            ;;
        *) # invalid
            echo "Invalid choice. Please give a number of a valid option."
            ;;
    esac

    end_time=$(date +%s)
    elapsed_time=$((end_time - start_time))

    echo "Finished this section, took $elapsed_time seconds"
    read -p "Press Enter to continue..."
done

onExit

# secure DNS
# Failed to enable unit: Unit file update-notifier.service does not exist.
