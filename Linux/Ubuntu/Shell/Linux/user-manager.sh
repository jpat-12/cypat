#!/bin/bash


sleep 5
echo "Creating directory for user files"
sleep 2
user_dir="/root/users"

# Create the directory if it doesn't exist
mkdir -p "$user_dir"

# Function to remove users from a list
remove_users() {
    list_file="$1"
    target_file="$2"
    while IFS= read -r user; do
        sed -i "/^$user$/d" "$target_file"
    done < "$list_file"
}

echo "Task 1: Get a list of all users and save it to users-all.txt"
sleep 2
getent passwd | cut -d: -f1 > "$user_dir/users-all.txt"

echo "Task 2: Remove Default users from users-all.txt"
sleep 2
cat << EOF > "$user_dir/users-default.txt"
root
daemon
bin
sys
sync
games
man
lp
mail
news
uucp
proxy
www-data
backup
list
irc
gnats
nobody
systemd-network
systemd-resolve
messagebus
systemd-timesync
syslog
_apt
tss
uuidd
systemd-oom
tcpdump
avahi-autoipd
usbmux
dnsmasq
kernoops
avahi
cups-pk-helper
rtkit
whoopsie
sssd
speech-dispatcher
nm-openvpn
saned
colord
geoclue
pulse
gnome-initial-setup
hplip
gdm
_rpc
statd
sshd
EOF

remove_users "$user_dir/users-default.txt" "$user_dir/users-all.txt"

echo "Task 3: Add Authorized users to users-authorized.txt"
sleep 2
echo "Please enter ONLY the Authorized Users from the readme into the file that will be created. Do you understand? (y/n)"
read answer
if [[ $answer == "n" ]]; then
  exit 1
fi
nano "$user_dir/users-authorized.txt"

echo "Task 4: Remove Authorized users from users-all.txt"
sleep 2
remove_users "$user_dir/users-authorized.txt" "$user_dir/users-all.txt"

echo "Task 5: Add Admin users to users-admin.txt"
sleep 2
echo "Please enter ONLY the Admin Users from the readme into the file that will be created. Do you understand? (y/n)"
read answer
if [[ $answer == "n" ]]; then
  exit 1
fi
nano "$user_dir/users-admin.txt"

echo "Task 6: Remove Admin users from users-all.txt"
sleep 2
remove_users "$user_dir/users-admin.txt" "$user_dir/users-all.txt"

echo "Task 7: Add the current user to users-current.txt"
sleep 2
echo "Please enter the current user from the readme into the file that will be created. Do you understand? (y/n)"
read answer
if [[ $answer == "n" ]]; then
  exit 1
fi
nano "$user_dir/users-current.txt"

echo "Task 8: Remove Admin users from users-admin.txt"
sleep 2
current_user=$(whoami)
sed -i "/^$current_user$/d" "$user_dir/users-admin.txt"

echo "Task 9: Ask if user from users-all.txt should be removed"
sleep 2
while IFS= read -r user; do
    echo "Should the user $user be removed? (y/n)"
    read answer
    if [[ $answer == "y" ]]; then
        echo "$user" >> "$user_dir/users-remove.txt"
    fi
    if [[ $answer == "n" ]]; then
        echo "$user" >> "$user_dir/users-keep.txt"
    fi
done < "$user_dir/users-all.txt"

echo "Task 10: Remove admin privileges from users-authorized.txt"
sleep 2
users_to_remove_admin_privs=$(cat "$user_dir/users-authorized.txt")
for user in $users_to_remove_admin_privs; do
    sudo deluser "$user" sudo
done


# Read the list of users to delete from the file
users_to_delete=$(cat /root/users/users-all.txt)

# Iterate over the list of users and delete them
for user in $users_to_delete; do
  sudo userdel -r $user
done

echo "_________________"
echo "_________________" 
echo "Changing Passwords"
echo "_________________"
echo "_________________"
sleep 2

echo "Printing users to /root/users/users-all2.txt"
sleep 2

# Get a list of all users
users=$(getent passwd | cut -d: -f1)

# Print the list of users to the file
for user in $users; do
  echo $user >> /root/users/users-all2.txt  
done

echo "Removing default users from /root/users/users-all2.txt"
sleep 2
# Get a list of all users from /root/users-default.txt
users_to_remove=$(cat /root/users/users-default.txt)

# Iterate over the list of users and remove them from /root/users-all.txt
for user in $users_to_remove; do
  # Remove the user from /root/users/users-all.txt
  sed -i "/^$user$/d" /root/users/users-all2.txt
done

# Create a list of all the users you provided
# Ask the user if they want to proceed
echo "Please enter ONLY the users that you are logged in under (not root) Do you understand? (y/n)"
read answer
# If the answer is no, exit the script
if [[ $answer == "n" ]]; then
  exit 1
fi
nano /root/users/user-current.txt

echo "The users at /root/users/users-all2.txt will be deleated" 
echo "This script will open that file, when you close it the users listed will be deleated" 
echo "Please make sure the users inside actually need to be deleated."

nano /root/users/users-all2.txt

echo "removing current user from /root/users/users-all2.txt"
sleep 2
# Get a list of all users from /root/users-authorized.txt
users_to_remove=$(cat /root/users/users-current.txt)

# Iterate over the list of users and remove them from /root/users-all.txt
for user in $users_to_remove; do
  # Remove the user from /root/users/users-all.txt
  sed -i "/^$user$/d" /root/users/users-all2.txt
done

echo "Changing passwords of users in /root/users/users-all2.txt"
# Define the new password
new_password="G0\$1vilAirPatrol"  # Note: Use \$ to escape the dollar sign

# Check if the user list file exists
user_list_file="/root/users/users-all2.txt"
if [ ! -f "$user_list_file" ]; then
  echo "User list file $user_list_file does not exist."
  exit 1
fi

# Iterate over each user in the list and set their password
while IFS= read -r username; do
  # Check if the user exists before changing the password
  if id "$username" &>/dev/null; then
    echo "Changing password for user: $username"
    echo "$username:$new_password" | sudo chpasswd
  else
    echo "User $username does not exist."
  fi
done < "$user_list_file"

echo "-----------------------"
echo "List all groups and add new group"
echo "-----------------------"

echo "Listing all groups..."
getent group | cut -d: -f1
read -p "Do you want to add a new group? (y/n) " add_group

if [ "$add_group" == "y" ]; then
  read -p "Enter the name of the new group: " new_group
  sudo groupadd $new_group
fi

echo "-----------------------"
echo "Would you like to add a user to a group?"
echo "-----------------------"

echo "Listing all groups..."
getent user | cut -d: -f1

while true; do
  read -p "Do you want to add a user to a group? (y/n) " add_user

  if [ "$add_user" == "y" ]; then
    read -p "Enter the name of the user: " new_user
    read -p "Enter the name of the group: " new_group1
    sudo gpasswd -a $new_user $new_group1
    echo "User $new_user added to $new_group1"
    sleep 2
  else
    break
  fi
done




echo "Password change process completed."
