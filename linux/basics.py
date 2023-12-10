import subprocess
import time

def run_command(command):
    subprocess.run(command, shell=True, check=True)
def clear():
    run_command("clear")
def forensic_questions():
    try:
        print("Opening Forensic Questions")
        run_command("nano Desktop/Forensic Question 1")
        run_command("nano Desktop/Forensic Question 2")
        input("Press enter to continue")
    except Exception as e:
        print(e)
def packages():
    packagemanager = ""
    while packagemanager != "apt" and "yum" and "apt-get":
        try:
            packagemanager = input("Enter the package manager this system uses (apt, yum, apt-get): ").lower()
            if packagemanager != "apt" and "yum" and "apt-get":
                print("Enter a valid package manager. ")
        except ValueError:
            print("Enter a valid value.")
    if packagemanager == "apt":     
        next_step = input("Press enter to proceed to next step(updates), type 'skip' to skip this step")
        if next_step == "skip":
            return   
        run_command("sudo apt update -y")
        run_command("sudo apt upgrade -y")
        run_command("sudo apt autoremove -y")
        clear()
        print("Updates completed")

        while True:
            apptoadd = input("Enter a package to add (q to stop): ")
            if apptoadd == "q":
                break
            try:
                run_command(f"sudo apt install {apptoadd}")
            except Exception as e:
                print("Error:", e)

        while True:
            apptorm = input("Enter a package to remove (q to stop): ")
            if apptorm == "q":
                break
            try:
                run_command(f"sudo apt purge {apptorm}")
            except Exception as e:
                print("Error:", e)
    
def firewall():
    next_step = input("Press enter to proceed to next step(configuring firewall), type 'skip' to skip this step")
    if next_step == "skip":
            return   
    run_command("sudo apt install ufw")
    run_command("sudo ufw enable")
    run_command("sudo ufw default deny incoming")
    run_command("sudo ufw default allow outgoing")
    run_command("sudo ufw allow ssh")
    clear()
def ssh():
    next_step = input("Press enter to proceed to next step(configuring ssh), type 'skip' to skip this step")
    if next_step == "skip":
        return   
    run_command("sudo apt install ssh")

    run_command("sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config") # Disables root login for ssh

    print("SSH root login disabled.")

    # print("Enforcing SSH key authentication...")
    #Disable password authentication in SSH server configuration
    # This code does not work
    # run_command("sudo sed -i s/PasswordAuthentication yes/PasswordAuthentication no/ /etc/ssh/sshd.config")

    run_command("sudo service ssh restart") # Restarts SSH
    time.sleep(5)
    clear()
    print("SSH configured")
def services():
    next_step = input("Press enter to proceed to next step(configuring services), type 'skip' to skip this step")
    if next_step == "skip":
        return
    command = "systemctl list-units --type=service --state=running --no-pager --plain --no-legend"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, _ = process.communicate()

    services = output.decode().strip().split("\n")

    for service in services:
        print(service)
    
    badServices = ["nginx", "apache2"]

    for badService in badServices:
        try:
            run_command(f"sudo systemctl stop {badService}")
            run_command(f"sudo systemctl disable {badService}")
        except Exception as e:
            print("Error:", e)

    while True:
        srvc = input("Enter a desired service to delete(q to stop): ")

        if srvc == "q" or "Q":
            break
        try:
            run_command(f"sudo systemctl stop {srvc}")
            run_command(f"sudo systemctl disable {srvc}")
        except Exception as e:
            print("Error:", e)
    clear()
    print("Services configured")
def all():
    forensic_questions()
    packages()
    firewall()
    ssh()
    services()
    clear()
    print("Basics completed")