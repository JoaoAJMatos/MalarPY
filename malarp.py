import scapy.all as scapy
from pick import pick # Pick is used to create interactive menus
import sys
import time
import ipaddress
import pyfiglet
import os
import nmap
import netifaces

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
    

# Get all hosts connected to your network
def getNetworkIPs(gateway = netifaces.gateways()['default'][netifaces.AF_INET][0]): # Use your default gateway if no gateway is passed
    nm = nmap.PortScanner()
    nm.scan(hosts = gateway, arguments = '-sn')
    host_list = [(host, nm[host]['status']['state']) for host in nm.all_hosts() if host != gateway] # Get list of all UP hosts in the network
    return host_list
    

def ARPSpoofer():
    asciiBanner = pyfiglet.figlet_format("ARP Spoofer")
    

    options = ["Manual selection", "Find hosts", "Quit"]
    option, index = pick(options, asciiBanner, indicator = ">", default_index = 0)

    clearTerminal()
    print(asciiBanner)

    if index == 1:

        while True:
            gateway = input("Gateway [default '{}'] ('q' to quit):".format(netifaces.gateways()['default'][netifaces.AF_INET][0]))

            if gateway == '':
                print("Fetching default gateway")
                allHosts = getNetworkIPs()

                if len(allHosts) == 0:
                    print("No hosts found... quiting")
                    time.sleep(0.7)
                    

                else:
                    print("Found {} host/s".format(len(allHosts)))

            elif gateway != 'q' and gateway != '':

                if isValidIP(gateway)[0]:
                    print("Fetching '{}'".format(gateway))
                    allHosts = getNetworkIPs(gateway)

                    if len(allHosts) == 0:
                        print("No hosts found... quiting")
                        time.sleep(0.7)

                    else:
                        print("Found {} host/s".format(len(allHosts)))

                else:
                    print("'{}' is not a valid IP".format(gateway))
                    time.sleep(0.8)

            elif gateway.upper() == 'Q':
                break

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
