import subprocess
from util import run_command
from util import clear

def manage_users():
    next_step = input("Press enter to proceed to next step(managing users), type 'skip' to skip this step")
    if next_step == "skip": return   
    # Declares lists of authorized admins and authorized users
    authadmns = []
    authusrs = []

    while True: # Filling authorized admin list
        authadmn = input("Enter an authorized admin (press q to stop, r to remove last input)): ").lower()
        if authadmn == "q": break
        elif authadmn == "r":
            authadmns.pop()
            continue
        authadmns.append(authadmn) # Adds the authadmn variable to the authorized admins array

    while True: # Filling authorized user list
        authusr = input("Enter an authorized user (press q to stop, r to remove last input)): ").lower()
        if authusr == "q": break
        elif authusr == "r":
            authusrs.pop()
            continue
        authusrs.append(authusr) # Adds the authusr variable to the authorized users array

    # Cuts the output into parts by ":" and shows only the first part of each line
    usrlist = subprocess.run(["cut", "-d:", "-f1", "/etc/passwd"], capture_output=True, text=True).stdout.split()
    
    # Declares array of default users that we don't want to mess with
    defaultusr = input("Enter default root user: ").lower() # Asks for the default root user so that the script doesn't mess with the default root user
    defaultusrs = ["postgres", "lightdm", "systemd-coredump", "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats", "nobody", "systemd.network", "systemd-resolve", "messagebus", "systemd-timesync", "syslog", "_apt", "tss", "uuidd", "avahi-autoipd", "usbmux", "dnsmasq", "kernoops", "avahi", "cups-pk-helper", "rtkit", "whoopsie", "sssd", "speech-dispatcher", "nm-openvpn", "saned", "colord", "geoclue", "pulse", "gnome-initial-setup", "hplip", "gdm", "_rpc", "statd", "sshd", "systemd-network", "systemd-oom", "tcpdump"]
    defaultusrs.append(defaultusr)

    for defaultusr in defaultusrs:
        try:
            usrlist.remove(defaultusr) # Removes default users from userlist 
        except ValueError: continue

    for usr in usrlist: # Loops through every user in the user list
        try:
            if usr not in authusrs + authadmns: # If user is not on any of the lists
                print(f"Deleting {usr}")
                run_command(f"sudo deluser {usr}") # Deletes the user
                usrlist.remove(usr) # Removes the user from the array to make looping through it faster

            subprocess.run(["passwd", usr], input=b"Cyb3rP@triot24!\nCyb3rP@triot24!\n", check=True) # Sets passwords
            print(f"\nSuccessfully changed password for {usr}")

            # Setting correct user permissions
            groups = subprocess.run(["groups", usr], capture_output=True, text=True).stdout.split() # Declares a list of user's groups

            if "sudo" in groups and usr not in authadmns: # If they have admin permissions and they are not an authorized admin
                print(f"Removing {usr} from group 'sudo'")
                run_command(f"sudo deluser {usr} sudo") # Removes the user from group sudo, essentially removing admin permissions
            elif "sudo" not in groups and usr in authadmns: # If they do not have admin permissions and they are an authorized admin
                print(f"Adding {usr} to group 'sudo'")
                run_command(f"sudo adduser {usr} sudo") # Adds the user to group sudo, adding admin permissions
        except Exception as e: print(e)

    for authadm in authadmns:
        if authadm not in usrlist: 
            print("Adding user {authadm}")
            try:
                subprocess.run(["sudo", "adduser", authadm], input=b"Cyb3rP@triot24!\nCyb3rP@triot24!\n\n\n\n\n\n\n")
            except Exception as e:
                print("Error:", e)
    for authusr in authusrs:
        if authusr not in usrlist: 
            try:
                subprocess.run(["sudo", "adduser", authusr], input=b"Cyb3rP@triot24!\nCyb3rP@triot24!\n\n\n\n\n\n\n")
            except Exception as e:
                print("Error:", e)

    while True:
        usrtoadd = input("Enter a user to add (press q to stop, r to remove last input)): ").lower()

        if usrtoadd == "q": break
        elif usrtoadd == "r":
            usrtoadd.pop()
            continue
        try:
            run_command(f"sudo useradd {usrtoadd}")
        except Exception as e:
            print("Error:", e)

    run_command("sudo passwd -l root")
    clear()
    print("Users managed")
def manage_groups():
    next_step = input("Press enter to proceed to next step(managing groups), type 'skip' to skip this step")
    if next_step == "skip": return   
    while True:
        grouptoadd = input("Enter a group to add (press q to stop, r to remove last input): ").lower()
        if grouptoadd == "q": break
        elif grouptoadd == "r":
            grouptoadd.pop()
            continue
        try:
            run_command(f"sudo addgroup {grouptoadd}")
        except Exception as e:
            print("Error:", e)
    while True:
        grouptorm = input("Enter a group to remove (q to stop): ").lower()
        if grouptorm == "q": break
        run_command(f"sudo delgroup {grouptorm}")
    while True:
        usertoaddtogroup = input("Enter a user to add to a group (q to stop) ex: 'group user'\t").lower()
        if usertoaddtogroup == "q": break
        usertoaddtogroup = usertoaddtogroup.split()
        try:
            run_command(f"sudo adduser {usertoaddtogroup[1]} {usertoaddtogroup[0]}")
        except Exception as e:
            print("Error:", e)
    clear()
    print("Groups managed")
def all():
    manage_users()
    manage_groups()