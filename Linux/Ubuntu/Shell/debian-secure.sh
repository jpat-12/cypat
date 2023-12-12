#!/bin/bash
echo "This is the best cyber pat script ever made"
echo "-----------------------"
echo "Task 1: Set ufw"
echo "-----------------------"
sudo apt-get install ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw enable
sudo ufw allow ssh
sudo ufw enable

echo "Detect and manage open ports"
echo "Detecting open ports..."
#add info about what netstat & awk & sed do 

sudo netstat -tulpn | awk '{print $4,$7}' | sed 's/.*://' | sort -n -u | while read line
do
  port=$(echo $line | awk '{print $1}')
  service=$(echo $line | awk '{print $2}')
  echo "Port $port is being used by $service"
  read -p "Do you want to keep port $port open? (y/n) " answer
  if [ "$answer" == "y" ]; then
    echo "Keeping port $port open"
    sudo ufw allow $port/tcp
  else
    echo "Closing port $port"
    sudo ufw deny $port/tcp
  fi
done


echo "-----------------------"
echo "Task 2: Set SSH"
echo "-----------------------"

sudo apt-get update
sudo apt-get install openssh-server -y
# Backup the SSH configuration file
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
# Disable root login by modifying the SSH configuration
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
# Restart the SSH service to apply changes
sudo systemctl start ssh
echo "Waiting 5 Seconds"
sleep 5

echo "-----------------------"
echo "Task 3: Check for updates daily"
echo "-----------------------"
sleep 3
echo "Open Software & Updates->Settings->Updates->Daily->Close"
echo "Press any button to continue" 
read answer

echo "-----------------------"
echo "Task 4: FTP Server"
echo "-----------------------"
# Prompt the user for their choice
echo "Would you like to install or remove the FTP server from Ubuntu 22.04?"
echo "Enter 'install' or 'remove':"
read choice
# Check the user's choice and perform the corresponding action
if [[ $choice == "install" ]]; then
  # Install the FTP server
  sudo apt-get install vsftpd

  # Start the FTP server
  sudo systemctl start vsftpd

  # Enable the FTP server to start at boot
  sudo systemctl enable vsftpd

  # Let the user know that the FTP server has been installed
  echo "The FTP server has been installed."
elif [[ $choice == "remove" ]]; then
  # Stop the FTP server
  sudo systemctl stop vsftpd

  # Disable the FTP server from starting at boot
  sudo systemctl disable vsftpd

  # Remove the FTP server
  sudo apt-get remove vsftpd

  # Let the user know that the FTP server has been removed
  echo "The FTP server has been removed."
else
  # If the user enters an invalid choice, let them know
  echo "Invalid choice. Please enter 'install' or 'remove'."
fi
sudo systemctl status vsftpd
#echo "Type "sudo systemctl status vsftpd" to see if FTP is active or not."
#echo "Press any button to continue" 
#read answer

echo "-----------------------"
echo "Task 5: Prohibited software"
echo "-----------------------"
sudo apt-get purge ophcrack -y
sudo apt-get purge wireshark -y
sudo apt-get autoremove -y
sudo systemctl stop nginx apache2
sudo systemctl disable nginx
sudo systemctl stop apache2
sudo systemctl disable apache2
#sudo systemctl stop cups
#sudo systemctl disable cups
sudo systemctl stop avahi-daemon
sudo systemctl disable avahi-daemon
sudo apt-get purge samba -y
sudo apt-get purge telnet -y


echo "Get a list of all installed apps"
apps=$(dpkg --get-selections | awk '{print $1}')
echo "disregard the next few lines "


# Define a function to prompt the user if they want to remove an app
#function prompt_user() {
#    app_name=$1
#
#   # Check if the app is installed
#    if [ $(dpkg-query -s "$app_name" 2>/dev/null | grep -c "Status: install ok installed") -eq 1 ]; then
#        # Get the app description
#        app_description=$(apt show "$app_name" | grep -Po '(?<=Description: ).*')
#
#        # Prompt the user if they want to remove the app
#        echo "Would you like to remove the app '$app_name'? ($app_description)"
#        read -p "[y/N] " response
#
#        # Remove the app if the user confirms
#        if [ "$response" == "y" ]; then
#            sudo apt remove "$app_name"
#   fi
#}

# Loop through the non-default apps
#for app in $apps; do
#    # Skip essential apps
#    if [[ "$app" == "apt" || "$app" == "apt-utils" || "$app" == "base-files" || "$app" == "bash" || "$app" == "coreutils" || "$app" == "cpio" || "$app" == "dash" || "$app" == "dpkg" || "$app" == "e2fsprogs" || "$app" == "findutils" || "$app" == "gawk" || "$app" == "grep" || "$app" == "gzip" || "$app" == "iproute2" || "$app" == "less" || "$app" == "libc6" || "$app" == "make" || "$app" == "man-db" || "$app" == "mawk" || "$app" == "mount" || "$app" == "neofetch" || "$app" == "net-tools" || "$app" == "openssh-client" || "$app" == "openssh-server" || "$app" == "openssl" || "$app" == "patch" || "$app" == "perl" || "$app" == "procinfo" || "$app" == "psmisc" || "$app" == "sed" || "$app" == "sensible-utils" || "$app" == "sudo" || "$app" == "tar" || "$app" == "util-linux" || "$app" == "vim" ]]; then
#        continue
#    fi
#
#    # Prompt the user if they want to remove the app
#    prompt_user "$app"
#done

echo "-----------------------"
echo "Task 6: Search For Media"
echo "-----------------------"
find /home/ -type f -name "*.mp3" -o -name "*.mp4" -o -name "*.mov" -o -name "*.avi" -o -name "*.mkv"
echo "press any button to continue"
read choice
# Get a list of all media files in /home/
media_files=$(find /home/ -type f -name "*.mp3" -o -name "*.mp4" -o -name "*.mov" -o -name "*.avi" -o -name "*.mkv")

# Loop through the media files
#rename to name.mp3.txt
for media_file in $media_files; do

    # Get the native directory of the media file
    native_directory=$(dirname "$media_file")

    # Check if the media file is in its native directory
    if [[ "$media_file" != "$native_directory/$media_file" ]]; then
        # Ask the user if they want to rename the media file to its native directory
        echo "Do you want to rename the media file '$media_file' to its native directory '$native_directory/$media_file'? (y/N)"
        read -p " " response

        # Rename the media file if the user confirms
        if [[ "$response" == "y" ]]; then
            mv "$media_file" "$native_directory/$media_file"
        fi

        # Ask the user if they want to remove the old version of the media file
        echo "Do you want to remove the old version of the media file '$media_file'? (y/N)"
        read -p " " response

        # Remove the old version of the media file if the user confirms
        if [[ "$response" == "y" ]]; then
            rm "$media_file"
        fi
    fi
done

echo "-----------------------"
echo "Task 7: Set up automatic security updates"
echo "-----------------------"

sudo apt-get install unattended-upgrades
sudo dpkg-reconfigure --priority=low unattended-upgrades


echo "-----------------------"
echo "Task 8: Setting password policy"
echo "-----------------------"
sudo sed -i 's/^PASS_MAX\_REPEATS.*/PASS_MAX_REPEATS\t5/' /etc/login.defs

echo "-----------------------"
echo "Maximum password age - 90 days for users, 30 days for admin"
echo "-----------------------"
sudo sed -i 's/^PASS\_MAX\_DAYS.*/PASS_MAX_DAYS\t90/' /etc/login.defs
sudo sed -i 's/^PASS\_MAX\_DAYS\_ADMIN.*/PASS_MAX_DAYS_ADMIN\t30/' /etc/login.defs

echo "-----------------------"
echo "Minimum password age - 15 days"
echo "-----------------------"

sudo sed -i 's/^PASS\_MIN\_DAYS.*/PASS_MIN_DAYS\t15/' /etc/login.defs

echo "-----------------------"

echo "Minimum password length - 10 characters"
echo "-----------------------"

sudo sed -i 's/^PASS\_MIN\_LEN.*/PASS_MIN_LEN\t10/' /etc/login.defs

echo "-----------------------"
echo "Password must meet complexity requirements - Enabled"
echo "-----------------------"

sudo apt-get install libpam-pwquality
sudo sed -i 's/^password.*requisite.*pam_pwquality\.so.*/password requisite pam_pwquality.so try_first_pass retry=3 minlen=10 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password

echo "-----------------------"
echo "Store passwords with reversible encryption - Disabled"
echo "-----------------------"

sudo sed -i 's/^#*\s*store\-cleartext\-passwords.*/store-cleartext-passwords\ =\ no/' /etc/samba/smb.conf
sudo service smbd restart

echo "-----------------------"
echo "Task 9: Account lockout policy"
echo "-----------------------"

echo "Account lockout duration - 30 minutes"
sudo apt-get install fail2ban
sudo sed -i 's/^bantime\ =.*/bantime\ =\ 1800/' /etc/fail2ban/jail.local

echo "Account lockout threshold - 10 invalid login attempts"
sudo sed -i 's/^maxretry\ =.*/maxretry\ =\ 10/' /etc/fail2ban/jail.local

echo "Reset account lockout counter after - 30 minutes"
sudo sed -i 's/^findtime\ =.*/findtime\ =\ 1800/' /etc/fail2ban/jail.local

sudo service fail2ban restart


echo "-----------------------"
echo "Task 10: Software and Updates policy"
echo "-----------------------"

echo "Software and Updates policy"
echo "Setting software and updates policy..."

echo "Important security updates (xenial-security) - Enable"
sudo sed -i 's/^# deb-src/deb-src/' /etc/apt-get/sources.list
sudo sed -i 's/^# deb/deb/' /etc/apt-get/sources.list
sudo apt-get-get update
sudo apt-get-get install -y unattended-upgrades
sudo sed -i 's/^\/\/\s\{0,\}"\${distro_id}:\${distro_codename}-security";/\"\${distro_id}:\${distro_codename}-security";/' /etc/apt-get/apt-get.conf.d/50unattended-upgrades


echo "-----------------------"
echo "Task 11: Configure GDM3"
echo "-----------------------"
sudo dpkg-reconfigure gdm3


echo "-----------------------"
echo "Task 12: Remove Keyloggers"
echo "-----------------------"
# Get a list of all installed applications
applications=$(apt-get list --installed)

# Filter the list to only include keylogging applications
keylogging_applications=$(echo "$applications" | grep -E "keylogger|keystroke logger")

# Uninstall each keylogging application
for application in $keylogging_applications; do
    sudo apt-get remove "$application"
done

echo "-----------------------"
echo "Task 13: No keepalive or unattended sessions"
echo "-----------------------"
ClientAliveInterval 300
ClientAliveCountMax 0
clear
echo "-----------------------"
echo "Task 14: Disable obsolete rsh settings"
echo "-----------------------"
IgnoreRhosts yes
clear 
echo "-----------------------"
echo "Task 15: Check sshd_config file for correctness before restart"
echo "-----------------------"
sudo sshd -t
clear 

echo "-----------------------"
echo "Task 16: Set up auditing"
echo "-----------------------"
apt-get-get install auditd && auditctl -e 1
clear
echo "-----------------------"
echo "Task 17: Remove Samba-related"
echo "-----------------------"
apt-get-get remove .*samba.* .*smb.*
clear 
echo "-----------------------"
echo "Task 18: Remove any downloaded "hacking tools""
echo "-----------------------"
find /home/ -type f \( -name "*.tar.gz" -o -name "*.tgz" -o -name "*.zip" -o -name "*.deb" \)
clear
echo "-----------------------"
echo "Task 19: Install bum for a graphical interface"
echo "-----------------------"
apt-get-get install bum
clear


echo "This script is complete" 
echo "Please run <  cd /root/Secure-Linux && /root/Secure-Linux/user-manager.sh  >" 
