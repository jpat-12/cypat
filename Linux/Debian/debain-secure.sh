#!/bin/bash
echo "This is the best cyber pat script ever made"
echo "-----------------------"
echo "Task 1: Set ufw"
echo "-----------------------"
sudo apt install ufw
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

clear 

echo "-----------------------"
echo "Task 2: Set SSH"
echo "-----------------------"

sudo apt update
sudo apt install openssh-server -y
# Backup the SSH configuration file
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
# Disable root login by modifying the SSH configuration
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
# Restart the SSH service to apply changes
sudo systemctl start ssh
echo "Waiting 5 Second"
sleep 5
sudo systemctl status ssh 
echo "Does SSH show that is is active? (y/n)"
read choice
if [[ $choice == "n" ]]; then
  sudo systemctl start ssh
  sudo systemctl status ssh
  # Let the user know that the FTP server has been removed
  echo "The SSH server should be started"
elif [[ $choice == "y" ]]; then
  echo "The SSH Moving onto next task"
else
  # If the user enters an invalid choice, let them know
  echo "Invalid choice. Please enter 'y' or 'n'."
fi

clear
echo "-----------------------"
echo "Task 3: Check for updates daily"
echo "-----------------------"
sleep 3
echo "Open Software & Updates->Settings->Updates->Daily->Close"
echo "Press any button to continue" 
read answer

clear
echo "-----------------------"
echo "Task 4: FTP Server"
echo "-----------------------"
# Prompt the user for their choice
echo "Would you like to install or remove the FTP server from Debian?"
echo "Enter 'install' or 'remove':"
read choice
# Check the user's choice and perform the corresponding action
if [[ $choice == "install" ]]; then
  # Install the FTP server
  sudo apt install vsftpd

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
  sudo apt remove vsftpd

  # Let the user know that the FTP server has been removed
  echo "The FTP server has been removed."
else
  # If the user enters an invalid choice, let them know
  echo "Invalid choice. Please enter 'install' or 'remove'."
fi
sudo systemctl status vsftpd

clear
echo "-----------------------"
echo "Task 5: Prohibited software"
echo "-----------------------"
sudo apt remove ophcrack 
sudo apt remove wireshark -y
sudo apt autoremove -y
sudo systemctl stop nginx apache2
sudo systemctl disable nginx
sudo systemctl stop apache2
sudo systemctl disable apache2
#sudo systemctl stop cups
#sudo systemctl disable cups
sudo systemctl stop avahi-daemon
sudo systemctl disable avahi-daemon

echo "Get a list of all installed apps"
apps=$(dpkg --get-selections | awk '{print $1}')
echo "disregard the next few lines "

# (The rest of the script remains unchanged)
# ...

clear
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

clear
echo "-----------------------"
echo "Task 7: Set up automatic security updates"
echo "-----------------------"

sudo apt install unattended-upgrades
sudo dpkg-reconfigure --priority=low unattended-upgrades

clear
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

sudo apt install libpam-pwquality
sudo sed -i 's/^password.*requisite.*pam_pwquality\.so.*/password requisite pam_pwquality.so try_first_pass retry=3 minlen=10 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password

echo "-----------------------"
echo "Store passwords with reversible encryption - Disabled"
echo "-----------------------"

sudo sed -i 's/^#*\s*store\-cleartext\-passwords.*/store-cleartext-passwords\ =\ no/' /etc/samba/smb.conf
sudo service smbd restart

clear
echo "-----------------------"
echo "Task 9: Account lockout policy"
echo "-----------------------"

echo "Account lockout duration - 30 minutes"
sudo apt install fail2ban
sudo sed -i 's/^bantime\ =.*/bantime\ =\ 1800/' /etc/fail2ban/jail.local

echo "Account lockout threshold - 10 invalid login attempts"
sudo sed -i 's/^maxretry\ =.*/maxretry\ =\ 10/' /etc/fail2ban/jail.local

echo "Reset account lockout counter after - 30 minutes"
sudo sed -i 's/^findtime\ =.*/findtime\ =\ 1800/' /etc/fail2ban/jail.local

sudo service fail2ban restart

clear
echo "-----------------------"
echo "Task 10: Software and Updates policy"
echo "-----------------------"

echo "Software and Updates policy"
echo "Setting software and updates policy..."

echo "Important security updates (buster-security) - Enable"
sudo sed -i 's/^# deb-src/deb-src/' /etc/apt/sources.list
sudo sed -i 's/^# deb/deb/' /etc/apt/sources.list
sudo apt-get update
sudo apt-get install -y unattended-upgrades
sudo sed -i 's/^\/\/\s\{0,\}"\${distro_id}:\${distro_codename}-security";/\"\${distro_id}:\${distro_codename}-security";/' /etc/apt/apt.conf.d/50unattended-upgrades

clear
echo "-----------------------"
echo "Task 11: Configure GDM3"
echo "-----------------------"
sudo dpkg-reconfigure gdm3

clear
echo "-----------------------"
echo "Task 12: Remove Keyloggers"
echo "-----------------------"
# Get a list of all installed applications
applications=$(apt list --installed)

# Filter the list to only include keylogging applications
keylogging_applications=$(echo "$applications" | grep -E "keylogger|keystroke logger")

# Uninstall each keylogging application
for application in $keylogging_applications; do
    sudo apt remove "$application"
done

echo "This script is complete" 
echo "Please run < cd /root/Secure-Linux && /root/cypat/Linux/Debian/user-manager.sh >"
