import subprocess

def run_command(command):
    subprocess.run(command, shell=True, check=True)
def updatesettings():
    print("Manual Task 1: Enable Automatic Updates")
    print("Step 1: Navigate to 'Software and Updates'")
    input("Press enter when ready...")
    print("Step 2: Naviaate to 'Updates'")
    input("Press enter when ready...")
    print("Step 3: Set 'Automatically check for updates' to 'Daily'")
    input("Press enter when ready...")
    print("Automatic Updates Enabled")
    run_command("clear")
def disableguest():
    print("Manual Task 2: Disable Guest Account")
def all():
    updatesettings()
    disableguest()