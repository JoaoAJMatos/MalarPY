# HELP File for MalarPY
import pyfiglet

from util import *

def help():
      clearTerminal()
      asciiBanner = pyfiglet.figlet_format("Help")
      print(asciiBanner)
      text = '''
[+] MalarPY | Your all-in-one hacking tool

[+] Functionalities:
    - ARP Spoofing         ->    Man In The Middle Attack
    - ARP Table            ->    Displays the current ARP table state for your network interfaces
    - Connected Machines   ->    Displays the IPs and possible names of every device connected to your network
    - Internet Cutoff      ->    Disables access to the internet to a machine on your local network
    - Whois Query          ->    Displays the result of a Whois query on a specified target
    - Phone Info           ->    Fetches info on a specified phone number
    - Help                 ->    Shows help file
    - Quit                 ->    Exits the program
'''

      print(text)
      waitForKeyStroke()
