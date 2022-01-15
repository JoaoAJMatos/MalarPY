# A set of utility functions
import os

def getHostOS(): # Get current operating system
    return os.name

def clearTerminal(): # Clear screen
    osName = getHostOS()

    if osName == 'posix':
        os.system("clear")
    else:
        os.system("cls")

# Wait for a key to be pressed before continuing
def waitForKeyStroke():
    osName = getHostOS()

    if osName == 'posix':
        os.system('read -s -n 1 -p "Press any key to continue"')
    else:
        os.system("pause")