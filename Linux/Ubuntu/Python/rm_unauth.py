import subprocess
from util import run_command
from util import clear

def find_unauth_files():
    run_command("cd /home/")
    try:
        file_paths = subprocess.run(["locate", "*.mp3", "*.mp4", "*.avi", "*.mkv"], capture_output=True, text=True, check=True).stdout.split("\n")
    except Exception as e:
        print(e)

    # TODO: Fix deleting files
    '''
    for file_path in file_paths:
        print(file_paths)
        rmfile = input("Do you want to remove the file at the path displayed?(y/n) ")
        if rmfile == "y":
            try:
                run_command(f"rm -r {file_path}")
            except Exception as e:
                print("Error:", e)
    '''

def rm_unath_apps():
    try:
        run_command("sudo apt purge ophcrack wireshark gnome-mines gnome-mahjonng") # Removes common unauthorized packages
    except Exception as e:
        print("Error:", e)

def all():
    find_unauth_files()
    rm_unath_apps()