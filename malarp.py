import scapy.all as scapy
from pick import pick # Pick is used to create interactive menus
import sys
import time
import ipaddress
import pyfiglet
import os

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
    "Connected Machines"
]

def getHostOS(): # Get current operating system
    return os.name


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

    

def menu():
    osName = getHostOS()

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
        option, index = menu()
        
        print("Starting {}".format(option))
        
    


if __name__ == "__main__":
    main(sys.argv[1:])
