# HELP File for MalarPY
import pyfiglet
import time

from util import *

def help():
      clearTerminal()
      asciiBanner = pyfiglet.figlet_format("Help")
      print(asciiBanner)
      text = '''
MalarPY | Your all-in-one hacking tool

Functionalities:
 - ARP Spoofing (Man In The Middle Attack)
 - Internet Cutoff (Disables access to the internet to a machine on your local network)
 -
'''

      print(text)
      waitForKeyStroke()
