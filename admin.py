import socket
import threading
from scapy.all import *
from scapy.all import ARP, Ether, srp
from scapy.config import conf
from scapy.layers import inet
import scapy.all as scapy
import rsa
import ipaddress

port_services = {   # mappa servizi porta
    20: "FTP data",
    21: "FTP",    
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    37: "Time",
    53: "DNS",   
    67: "DHCP Server",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",    
    88: "Kerberos",
    110: "POP3",  
    119: "NNTP",
    123: "NTP",
    137: "NetBIOS",     
    143: "IMAP", 
    161: "SNMP", 
    162: "SNMP Traps",
    179: "BGP",
    389: "LDAP",     
    443: "HTTPS", 
    465: "SMTPS",
    512: "Rexec",   
    513: "Rlogin",
    514: "RSH",     
    543: "KKRPM",  
    544: "KKRPMP",        
    547: "DHCPArchive",    
    548: "AFP",  
    554: "RTSP", 
    563: "NNTP over SSL",  
    587: "SMTP Auth",
    636: "LDAP over SSL",   
    993: "IMAP over SSL",     
    995: "POP3 over SSL",
    60000: "Server"   
}


class Admin:
    def __init__(self, PORT):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.public_key, self.private_key = rsa.newkeys(1024)
        self.public_partner = None
        self.device_finder(PORT)                                                                        # cerca il server nella rete locale

        self.nick = 'admin'
        self.password = input('Enter password for admin: ')
            
        print('Connected to the server\n')
        self.stop_thread = False

        self.myprivateip = ""

        receive_thread = threading.Thread(target=self.receive)                                           # thread per ricevere messaggi
        write_thread = threading.Thread(target=self.write)                                               # thread per inviare messaggi                    

        receive_thread.start()
        write_thread.start()
    
    def receive(self):                                                                                   # comportamento thread che riceve messaggi dal server
        while True:
            try:
                message = rsa.decrypt(self.client.recv(1024), self.private_key).decode('ascii')
                if message == 'NICK':
                    self.client.send(rsa.encrypt(self.nick.encode('ascii'), self.public_partner))
                    next_msg = rsa.decrypt(self.client.recv(1024), self.private_key).decode('ascii')
                    if next_msg ==  'PASS':
                        self.client.send(rsa.encrypt(self.password.encode('ascii'), self.public_partner))
                        if rsa.decrypt(self.client.recv(1024), self.private_key).decode('ascii') == 'REFUSE':
                            raise Exception('Connection refused, wrong password')
                elif message.startswith('TCP'):
                    self.tcp_port_scanner(message[4:])                   
                else:
                    print(message)
            except Exception as e:
                print(f"Error: {str(e)}")
                self.client.close()
                self.stop_thread = True
                break

    def tcp_port_scanner(self, ip_target):                                                                                                                                              
        print(f'Starting scan on {ip_target}...\n')
        for port in port_services:
            pkt =scapy.IP(dst=ip_target)/scapy.TCP(dport=port, flags='S', sport=RandShort(), seq=RandShort())       # pacchetto TCP con SYN flag impostato
            ans, unans = sr(pkt, timeout=2, verbose = 0)                                                            # sport rand per evitare problemi di firewall
            if ans:                                                                                                 # seq rand per evitare problemi di firewall
                for snd, rcv in ans:
                    if rcv[scapy.TCP].flags == 'SA':
                        print(f'Port {port} is open, service: {port_services[port]} online')
                        
                    else:
                        print(f'Port {port} is not reachable, service: {port_services[port]}, in answer: {rcv[scapy.TCP].flags}')
            else:
                print(f'Port {port} is closed, service: {port_services[port]} offline')
        
        print(f'\nScan on {ip_target} finished\n')

    def write(self):                                                                                    # comportamento thread che invia messaggi al server
        while True:
            if self.stop_thread:
                break

            message = f'{self.nick}: {input("")}'
            if message[len(self.nick)+2:].startswith('/'):
                self.special_commands(message)
            else:
                self.client.send(rsa.encrypt(message.encode('ascii'), self.public_partner))
    
    def special_commands(self, message):                                                                # gestione comandi speciali - di servizio che vengono                    
        if 'admin' in message[len(self.nick)+2+5:]:                                                     # inviati al server                   
            print('You are not allowed to action on other admin')
        else:
            if message[len(self.nick)+2:].startswith('/kick'):
                self.client.send(rsa.encrypt(f'KICK {message[len(self.nick)+2+6:]}'.encode('ascii'), self.public_partner))
            elif message[len(self.nick)+2:].startswith('/ban'):
                self.client.send(rsa.encrypt(f'BAN {message[len(self.nick)+2+5:]}'.encode('ascii'), self.public_partner))
            elif message[len(self.nick)+2:].startswith('/tcp'):
                self.client.send(rsa.encrypt(f'TCP {message[len(self.nick)+2+5:]}'.encode('ascii'), self.public_partner))

            elif message[len(self.nick)+2:].startswith('/su'):              
                _, raw_command, body = message.split(' ', 2)                                            
                self.client.send(rsa.encrypt(f'SU {body}'.encode('ascii'), self.public_partner))       # Invia il nome utente e il comando 
                print('\n')


    def device_finder(self, PORT):                                                                      # cerca il server nella rete locale
        ip_list = []
        
        print("Reaching the server...")
        target_ip = self.network_finder()                                                               # ottiene la subnet
        arp = ARP(pdst=target_ip)                                                                       # creazione pacchetto ARP
        
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")                                                          # creazione pacchetto Ether broadcast 
        packet = ether/arp
        result = srp(packet, timeout=3, verbose=0)[0]
        for sent, received in result:
            ip_list.append(received.psrc)
        
        ping = inet.IP(dst="8.8.8.8")/inet.ICMP()
        ip_list.append(ping.src)
        self.myprivateip = ping.src
        ip_list.reverse()                                                                               # il mio ip lo metto alla fine, ci metto di meno
                                                                                                        # all'inizio c'e il gateway
        for ip in ip_list:
            try:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.connect((ip, PORT)) 
                self.client = client

                print(f'Connected to {ip}')                                                             # se trova il server si connette
                self.public_partner = rsa.PublicKey.load_pkcs1(self.client.recv(1024))
                self.client.send(self.public_key.save_pkcs1("PEM"))
                
                break
            except Exception as e: 
                print(f'{str(e)}')
                pass

    def network_finder(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)        # indirizzo IP dell' host, ipv4 e UDP
        s.connect(("8.8.8.8", 80))                                  # DNS di Google come riferimento
        ip = s.getsockname()[0]
        s.close()

        net = ipaddress.ip_interface(f'{ip}/24').network            # ottiene la subnet
        print(str(net))
        return str(net)

client = Admin(60000)