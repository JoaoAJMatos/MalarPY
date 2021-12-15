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
    "Quit"
]

def getHostOS(): # Get current operating system
    return os.name


def clearTerminal(): # Clear screen
    osName = getHostOS()

    if osName == 'posix':
        os.system("clear")
    else:
        os.system("cls")


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
    res = scapy.srp(fullPacket, timeout = 2, verbose = verbose)[0]

    # Return MAC Address
    return res[0][1].hwsrc


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
def getNetworkIPs():
    # Get your IPv4
    IPAddr = getMyIPv4()

    subnetMask = '/' + str(getSubnetMask(IPAddr))

    # Try to fetch hosts with nmap
    nm = nmap.PortScanner()
    result = nm.scan(IPAddr + subnetMask, arguments = '-sn')
    allHosts = nm.all_hosts()

    if len(allHosts) > 0:
        return allHosts

    else:
        print("No hosts found...")
        time.sleep(2)
        return



def ARPSpoofer():
    asciiBanner = pyfiglet.figlet_format("ARP Spoofer")
    

    options = ["Manual selection", "Find hosts", "Quit"]
    option, index = pick(options, asciiBanner, indicator = ">", default_index = 0)

    clearTerminal()
    print(asciiBanner)

    if index == 1:

        print("Fetching the network... this may take a moment")

        allHosts = getNetworkIPs()

        if len(allHosts) == 0:
            print("Quiting")
            time.sleep(0.7)
                    
        else:
            print("Found {} host/s".format(len(allHosts)))
            time.sleep(1)

            for i in range(0, len(allHosts)):
                print("{} - {} ({})".format(i + 1, allHosts[i], socket.gethostbyaddr(allHosts[i])[0]))

            IP2Spoof = input("Select an IP to spoof: ")

    elif index == 2:
        return



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

            if index == len(options) - 1:
                clearTerminal()
                break
    
if __name__ == "__main__":
    main(sys.argv[1:])
