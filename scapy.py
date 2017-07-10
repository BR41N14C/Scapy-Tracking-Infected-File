# scapy module being imported
from scapy.all import *

# this variable is going to read the capture file
Packets = rdpcap('capture2.pcap')

""" these variables are the IP address and the MAC address values
    found in wireshark then I put them in a list
"""
Last_Number1 = '1'
Last_Number2 = '2'
Last_Number3 = '3'
Last_Number4 = '30'
IP = '192.168.0.'
MAC = '00:03:ff:98:98:0'
MAC2 = '00:03:ff:98:98:'
IPs = [
              IP + Last_Number1,
              IP + Last_Number2,
              IP + Last_Number3,
              IP + Last_Number4,
             ]

MACs = [
               MAC + Last_Number1,
               MAC + Last_Number2,
               MAC + Last_Number3,
               MAC2 + Last_Number4,
              ]

""" this for loop block is going to store what happens in the packets
    into the Storage then it will loop and each which packet has ARP In them
    then it will print to the terminal.
"""
Default_Address = 'ff:ff:ff:ff:ff:ff'
for Storage in Packets:  # what happens in Packets variable store it in Storage
    if Storage.haslayer(ARP):  # check if packet has ARP in them
        if Storage.dst != Default_Address:
            one = Storage.dst
            two = Storage.pdst
            three = Storage.psrc
            four = Storage.src
            spaces = "                               "
            if not(
                (IPs[0] == two and MACs[0] == one) or
                (IPs[1] == two and MACs[1] == one) or
                (IPs[2] == two and MACs[2] == one) or
                (IPs[3] == two and MACs[3] == one)
                  ):

                    print '> [Possible attackers IP] = '
                    print spaces + "IP = " + two + ''
                    print spaces + "MAC = " + one + '\n'
                    print '> [IP of attacker] = %s' % (IPs[MACs.index(one)])
                    print '> [MAC of attacker] = %s \n' % (one)
                    print '> [IP of target] = %s' % (three)
                    print '> [MAC of Target] = %s \n' % (four)
