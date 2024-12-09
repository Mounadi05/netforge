.PHONY: all up down console

all: up console

up:
	docker-compose up -d

down:
	docker-compose down



client_ip=$(shell docker inspect inquisitor-client-1 | grep \"IPAddress\" | tail -n 1)
attacker_ip=$(shell docker inspect inquisitor-attacker-1 | grep \"IPAddress\" | tail -n 1)
ftp-server_ip=$(shell docker inspect inquisitor-ftp-server-1| grep \"IPAddress\" | tail -n 1)

console:
	gnome-terminal -- bash -c "echo 'Connected to Client :$(client_ip)'; docker exec -it inquisitor-client-1 bash"
	gnome-terminal -- bash -c "echo 'Connected to Attacker :$(attacker_ip)'; docker exec -it inquisitor-attacker-1 bash"
	gnome-terminal -- bash -c "echo 'Connected to FTP Server :$(ftp-server_ip)'; docker logs -f inquisitor-ftp-server-1"