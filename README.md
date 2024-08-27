The purpose of the project is to implement a client-server architecture in which a server entity connects an indefinite number of clients. The entities that communicate through the server are of two types:

- Client: A simple client capable of exchanging messages with other clients connected to the server. The Client entity ‘models’ an employee using the system.
- Admin: A client capable of performing special operations such as closing the client’s communication with the server, executing commands with elevated permissions on a connected client’s device,
         and performing TCP port scans on clients. The Admin entity ‘models’ a system administrator.

This system is designed as a potential application on a corporate network, as it is not capable of accessing the internet. The project’s goal is to allow employees connected to the system to receive initial 
assistance from a technician so that if an employee encounters problems using their device, they can request immediate diagnostic intervention. The functionalities provided to the Admin are capable of making 
an initial assessment of the issues occurring on the requesting device.



For program testing:

- The Python version I used is 3.8.10; version 2.7.18 is not sufficiently updated for the application to function correctly.
- The Scapy version used is 2.4.3 (link ref -> https://github.com/secdev/scapy)
- The programs client.py, admin.py, and server.py must be run with administrator permissions (all tests I conducted were on Linux Mint systems).
- The password to launch an Admin client is ‘admin’.
- For BAN testing, the nickname ‘gogo’ is present in bans.txt
