import threading        #gestione thread
import socket           #gestione comunicazione client-server
import subprocess       #gestione comunicazione shell
import rsa

class Server:
    def __init__(self, PORT):

        self.PORT = PORT
        self.get_private_ip()                                                                           # ottiene l'ip privato del server
        self.port_command_control = 0                                                                   # 0 = apre porte, 1 = chiude porte

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)                                 # crea un socket ipv4 e tcp
        self.server.bind((self.HOST, self.PORT))                                                        # collega il socket all'host e alla porta
        self.server.listen()                                                                            # mette il socket in ascolto

        self.clients = []
        self.nicks = []
        self.addresses = []
        self.public_partners = []
        self.running = True                                                                             # variabile per chiudere il server

        self.public_key, self.private_key = rsa.newkeys(1024)                                           # genero le chiavi pubbliche e private
        

        print(f'Opening incoming transmissions on port {self.PORT}')
        self.port_handler()                                                                             # apre la porta di comunicazione

        print(f"Server on: {self.HOST}:{self.PORT}\n")
        self.receive()                                                                                  # avvia il server                 

    def broadcast(self, message, client):                                                               # invia un messaggio a tutti gli altri client connessi
        for client_to in self.clients:
            if client_to != client:
                client_to.send(rsa.encrypt(message, self.public_partners[self.clients.index(client_to)]))

    def handler(self, client):                                                                          # gestisce i messaggi ricevuti dai client
        client.settimeout(0.5)
        while True:
            try:
                if self.running:
                    message = rsa.decrypt(client.recv(1024), self.private_key) 
                    if message:
                        if message.decode('ascii')[0].isupper():                                        # se il messaggio inizia con una lettera maiuscola
                            self.admin_handler(client, message)                                         # gestisce il messaggio come un comando di servizio
                        else:
                            self.broadcast(message, client)
                    else:
                        raise Exception("Connection closed by client")
                else:
                    raise Exception("Server closed")                                                    # se il server è chiuso, solleva un'eccezione però server
                                                                                                        # restava collegato al client.recv in attesa di un messaggio
            except socket.timeout:                                                                      # quindi se non ricevo messaggi  passo alla iterazione successiva
                pass                                                                                    # e rivaluto la condizione del if self.running

            except Exception as e:
                print(f'{self.nicks[self.clients.index(client)]} disconnected')

                if client in self.clients:
                    self.broadcast(f'{self.nicks[self.clients.index(client)]} left the chatroom'.encode('ascii'), client)

                    self.remove_client(client)
                    break
    
    def admin_handler(self, client, message):                                                           # gestisce i comandi di servizio inviati dall'admin

        if self.nicks[self.clients.index(client)] == 'admin':                                       
            if message.decode('ascii').startswith('KICK'):                                              # operazione di kick
                name_to_kick = message.decode('ascii')[5:]     # stringa dopo kick + spazio                                     
                self.kick_user(name_to_kick, 0, client)         

            elif message.decode('ascii').startswith('BAN'):                                             # operazione di ban
                name_to_ban = message.decode('ascii')[4:]
                self.kick_user(name_to_ban, 1, client)
                with open('bans.txt', 'a') as f:
                    f.write(f'{name_to_ban}\n')
                print(f'{name_to_ban} was banned!') 
            
            elif message.decode('ascii').startswith('TCP'):                                             # operazione di scansione porte tcp
                name = message.decode('ascii')[4:]
                if name in self.nicks:
                    address = self.addresses[self.nicks.index(name)]
                    client.send(rsa.encrypt(f'TCP {address[0]}'.encode('ascii'), self.public_partners[self.clients.index(client)]))
                    
                else:
                    client.send(rsa.encrypt(f'Client [{name}] not found'.encode('ascii'), self.public_partners[self.clients.index(client)]))

            elif message.decode('ascii').startswith('SU'):                                              # operazione di esecuzione comandi su client
                command_key, target, command = message.decode('ascii').split(' ', 2)
                message = message.decode('ascii')

                if target in self.nicks:
                    target_index = self.nicks.index(target)
                    client_target = self.clients[target_index]

                    client_target.send(rsa.encrypt(f'SU {command}'.encode('ascii'), self.public_partners[target_index]))

                    client.send(rsa.encrypt(rsa.decrypt(client_target.recv(1024), self.private_key), self.public_partners[self.clients.index(client)]))
                else:
                    client.send(rsa.encrypt(f'Client [{target}] not found'.encode('ascii'), self.public_partners[self.clients.index(client)]))
        else:
            client.send(rsa.encrypt('Command was refused'.encode('ascii'), self.public_partners[self.clients.index(client)]))
        
                    
    
    def receive(self):                                                                                      # gestisce la connessione dei client
        while True:
            try:
                client, address = self.server.accept()                                                      
                print(f'Connected with {str(address)}')

                client.send(self.public_key.save_pkcs1("PEM"))                                                    # invia la chiave pubblica al client
                self.public_partners.append(rsa.PublicKey.load_pkcs1(client.recv(1024)))                          # riceve la chiave pubblica del client
                
                client.send(rsa.encrypt('NICK'.encode('ascii'), self.public_partners[-1]))                                                         
                nick = rsa.decrypt(client.recv(1024), self.private_key).decode('ascii')  

                with open('bans.txt', 'r') as f:
                    bans = f.readlines()

                if nick+'\n' in bans:                                                                       
                    client.send(rsa.encrypt('BAN'.encode('ascii'), self.public_partners[-1]))
                    self.public_partners.pop(-1)
                    client.close()
                    continue
                if nick == 'admin':
                    client.send(rsa.encrypt('PASS'.encode('ascii'), self.public_partners[-1]))
                    password = rsa.decrypt(client.recv(1024), self.private_key).decode('ascii')
                        
                    if password != 'admin':
                        client.send(rsa.encrypt('Refuse connection'.encode('ascii'), self.public_partners[-1]))
                        self.public_partners.pop(-1)
                        client.close()
                        continue

                self.nicks.append(nick)
                self.clients.append(client)
                self.addresses.append(address)

                print(f'Nickname of the client is {nick}')
                self.broadcast(f'{nick} joined the chat'.encode('ascii'), client)
                client.send(rsa.encrypt('Connected to the server'.encode('ascii'), self.public_partners[self.nicks.index(nick)]))

                thread = threading.Thread(target=self.handler, args=(client,))                              # crea un thread per ogni client connesso
                thread.start()                                                                              # parametri: metodo handler e connessione client                
            except KeyboardInterrupt:
                self.end_server()
                break
    
    def remove_client(self, client):
        nick = self.nicks[self.clients.index(client)]
        address = self.addresses[self.clients.index(client)]
        public_partner = self.public_partners[self.clients.index(client)]

        self.clients.remove(client)
        self.nicks.remove(nick)
        self.addresses.remove(address)
        self.public_partners.remove(public_partner)

        client.close()
    
    def get_private_ip(self):                                                                               # ottiene l'ip privato del server
        command = "ifconfig | grep 'inet ' | awk '{print $2}' | grep -v '127.0.0.1'"
        process = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
        output, error = process.communicate()
        if process.returncode == 0:
            self.HOST = output.decode('utf-8').strip()
        else:
            print(f"Error: {error.decode('utf-8')}")
            raise Exception('Error in getting private IP')
        
    def port_handler(self):                                                                                 # apro e chiudo la porta di comunicazione 
        if self.port_command_control == 0:
            command = ['sudo', 'iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '60000', '-j', 'ACCEPT'] #open port
        elif self.port_command_control == 1:
            command = ['sudo', 'iptables', '-D', 'INPUT', '-p', 'tcp', '--dport', '60000', '-j', 'ACCEPT'] #close port
        
        self.port_command_control  += 1

        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if result.returncode != 0:
            print('Error:', result.stderr.decode('utf-8'))
    
    def kick_user(self, name, type_of_kick, client):
        if name in self.nicks:
            name_index = self.nicks.index(name)
            client_to_kick = self.clients[name_index]
            client_to_kick.send(rsa.encrypt('KICK'.encode('ascii'), self.public_partners[name_index]))
            if type_of_kick == 0:
                self.broadcast(f'{name} has been kicked by an admin!'.encode('ascii'), client_to_kick)
            else:
                self.broadcast(f'{name} has been banned by an admin!'.encode('ascii'), client_to_kick)
        elif name not in self.nicks and type_of_kick == 0:
            client.send(rsa.encrypt('Client not found'.encode('ascii'), self.public_partners[self.clients.index(client)]))
    
    def end_server(self):                                                                                      # termino il server in maniera controllota
        # Chiudi il server e i client connessi
        self.running = False
        self.server.close()

        # Chiudo la porta di comunicazione
        print(f'\nClosing transmissions on port {self.PORT}')
        self.port_handler()
        print(f'Port {self.PORT} closed')
        
        exit(0)


server = Server(60000)
