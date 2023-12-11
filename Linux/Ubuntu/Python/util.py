import subprocess

def run_command(command):
    # Runs command in terminal
    subprocess.run(command, shell=True, check=True)

def clear():
    run_command("clear") # Clears screen