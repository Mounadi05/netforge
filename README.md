# ARP-SPOF (ARP Spoofing Demonstration)

A containerized environment for demonstrating ARP spoofing attacks and network security vulnerabilities.

## Overview

ARP-SPOF is an educational project that creates a controlled environment to demonstrate ARP spoofing attacks and their impact on network security. The project uses Docker containers to simulate a network with multiple clients, an FTP server, a chat server, and an attacker machine.

## Features

- **Containerized Network Environment**: Isolated network for safe experimentation
- **Multiple Client Machines**: Two client containers for demonstrating communication
- **FTP Server**: A functional FTP server for file transfer demonstrations
- **Chat Server**: A simple TCP-based chat server for real-time communication
- **Attacker Machine**: Pre-configured with tools for executing ARP spoofing attacks
- **ARP Spoofing Tool**: Custom `inquisitor.c` tool for performing man-in-the-middle attacks

## Components

### Network Setup

The project creates a Docker network (`ftp-net`) where all containers communicate with each other:

- **Client Containers**: Two identical client machines with basic networking tools
- **FTP Server**: Running vsftpd with preconfigured credentials
- **Chat Server**: A simple TCP chat server allowing communication between clients
- **Attacker**: Container with network analysis tools and the custom ARP spoofing utility

### Inquisitor Tool

The `inquisitor.c` program is a custom ARP spoofing tool that:

1. Sends forged ARP replies to targets on a specified network interface
2. Intercepts network traffic between victims
3. Can display packet contents in verbose mode
4. Requires a network interface to be specified as a command-line argument

## Getting Started

### Prerequisites

- Docker and Docker Compose
- Linux environment (for proper network functionality)
- `make` utility

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/mounadi05/arp-spof.git
   cd arp-spof
   ```

2. Build and start the containers:
   ```
   make
   ```

This will:
- Build all Docker containers
- Start the network environment
- Open terminal windows for each container

### Usage

#### Basic Usage

1. The `make` command will start all containers and open terminal windows for each
2. Interact with the client terminals to communicate via FTP or the chat server
3. Use the attacker terminal to execute ARP spoofing attacks

#### Running an ARP Spoofing Attack

1. In the attacker terminal, compile the inquisitor tool:
   ```
   gcc -o inquisitor inquisitor.c -lpthread
   ```

2. Get the IP and MAC addresses of target machines:
   ```
   ip addr
   arp -a
   ```

3. Execute the attack (replace with actual interface, IP/MAC addresses):
   ```
   ./inquisitor <interface> <victim1-ip> <victim1-mac> <victim2-ip> <victim2-mac> -v
   ```
   For example:
   ```
   ./inquisitor eth0 192.168.1.1 00:11:22:33:44:55 192.168.1.2 66:77:88:99:AA:BB -v
   ```

4. Observe the intercepted traffic in the attacker terminal

#### Using the Chat Server

1. From client terminals, connect to the chat server:
   ```
   nc chat-server 9099
   ```

2. Type messages to communicate between clients
3. With ARP spoofing active, the attacker can intercept these messages

#### Using the FTP Server

1. From client terminals, connect to the FTP server:
   ```
   ftp ftp-server
   ```

2. Login with credentials:
   - Username: mounadi
   - Password: te1234st

3. Transfer files between the server and clients

## Educational Purpose

This project is designed for educational purposes to demonstrate:

- How ARP spoofing attacks work
- The vulnerability of unencrypted network communications
- The importance of network security measures
- Practical network security concepts in a controlled environment

## Stopping the Environment

To stop all containers:
```
make down
```

## License

This project is intended for educational purposes only. Use responsibly and only in environments you have permission to test.

## Disclaimer

This tool should only be used in controlled environments for educational purposes. Unauthorized use of ARP spoofing techniques on networks without explicit permission is illegal and unethical.