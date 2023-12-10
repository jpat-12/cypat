import subprocess
from util import run_command

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