import basics
import mantasks
import users_groups
import policies
import rm_unauth
from util import run_command
from util import clear

'''
Written by Nathan Le
This is a Python script for securing a CyberPatriot Linux machine
This file runs all the other files in the folder
Be sure to run this script with administrative priveledges
'''
def understand():
    understand = input("Do you understand this script?(y/n):")
    if understand != "thisisthebestscript":
        run_command("sudo shutdown now")
    else:
        clear()

def main():
    understand()
    policies.all()
    basics.all()
    mantasks.all()
    users_groups.all()
    rm_unauth.find_unauth_files()

    print("System secured.")

if __name__ == "__main__":
    main()