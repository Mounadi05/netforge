.PHONY: all up down console

all: up console

up:
	docker-compose up -d

down:
	docker-compose down



client_ip1=$(shell docker inspect client1 | grep \"IPAddress\" | tail -n 1)
client_ip2=$(shell docker inspect client2 | grep \"IPAddress\" | tail -n 1)
attacker_ip=$(shell docker inspect attacker | grep \"IPAddress\" | tail -n 1)
ftp-server_ip=$(shell docker inspect ftp-server| grep \"IPAddress\" | tail -n 1)
chat-server_ip=$(shell docker inspect chat-server| grep \"IPAddress\" | tail -n 1)

console:
	gnome-terminal -- bash -c "echo 'Connected to Client1 :$(client_ip1)'; docker exec -it client1 bash"
	gnome-terminal -- bash -c "echo 'Connected to Client2 :$(client_ip2)'; docker exec -it client2 bash"
	gnome-terminal -- bash -c "echo 'Connected to Attacker :$(attacker_ip)'; docker exec -it attacker bash"
	gnome-terminal -- bash -c "echo 'Connected to FTP Server :$(ftp-server_ip)'; docker logs -f ftp-server"
	gnome-terminal -- bash -c "echo 'Connected to Chat Server :$(chat-server_ip)'; docker exec -it chat-server cat chat-server.log"