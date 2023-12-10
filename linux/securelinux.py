import basics
import mantasks
import users_groups
import policies
import rm_unauth

'''
Written by Nathan Le
This is a Python script for securing a CyberPatriot Linux machine
This file runs all the other files in the folder
'''

def main():
    rm_unauth.understand()
    policies.all()
    basics.all()
    mantasks.all()
    users_groups.all()
    rm_unauth.find_unauth_files()

    print("System secured.")

if __name__ == "__main__":
    main()