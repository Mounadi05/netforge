#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

int max_client = 2000;
int client[2000] = {-1};
char *message[2000];
fd_set cur, cur_write, cur_read;


void log_message(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "\n");
    fflush(stderr);
}
void ft_error()
{
	write(2,"Fatal error\n",strlen("Fatal error\n"));
	exit(1);
}
void ft_send(int fd, char *str)
{
	for(int i = 0; i < max_client;i++)
		if(client[i] != -1 && i != fd && FD_ISSET(i,&cur_write))
			send(i,str,strlen(str),0);
}
int extract_message(char **buf, char **msg)
{
	char	*newbuf;
	int	i;

	*msg = 0;
	if (*buf == 0)
		return (0);
	i = 0;
	while ((*buf)[i])
	{
		if ((*buf)[i] == '\n')
		{
			newbuf = calloc(1, sizeof(*newbuf) * (strlen(*buf + i + 1) + 1));
			if (newbuf == 0)
				return (-1);
			strcpy(newbuf, *buf + i + 1);
			*msg = *buf;
			(*msg)[i + 1] = 0;
			*buf = newbuf;
			return (1);
		}
		i++;
	}
	return (0);
}
char *str_join(char *buf, char *add)
{
	char	*newbuf;
	int		len;

	if (buf == 0)
		len = 0;
	else
		len = strlen(buf);
	newbuf = malloc(sizeof(*newbuf) * (len + strlen(add) + 1));
	if (newbuf == 0)
		return (0);
	newbuf[0] = 0;
	if (buf != 0)
		strcat(newbuf, buf);
	free(buf);
	strcat(newbuf, add);
	return (newbuf);
}

char* get_local_ip() {
    struct ifaddrs *ifaddr, *ifa;
    static char ip[16];
    
    if (getifaddrs(&ifaddr) == -1) {
        strcpy(ip, "unknown");
        return ip;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET)
            continue;

        if (strcmp(ifa->ifa_name, "lo") == 0)
            continue;

        struct sockaddr_in *addr = (struct sockaddr_in*)ifa->ifa_addr;
        inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
        
        if (strcmp(ip, "127.0.0.1") != 0)
            break;
    }

    freeifaddrs(ifaddr);
    return ip;
}

int main(int ac , char **av) {
    if (ac == 2) {
        int sockfd;
        struct sockaddr_in servaddr;
        // socket create and verification 
        sockfd = socket(AF_INET, SOCK_STREAM, 0); 
        if (sockfd == -1) ft_error();
        bzero(&servaddr, sizeof(servaddr)); 
        // assign IP, PORT 
        servaddr.sin_family = AF_INET; 
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        servaddr.sin_port = htons(atoi(av[1])); 
        // Binding newly created socket to given IP and verification 
        if ((bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr))) != 0) 
            ft_error();
        if (listen(sockfd, 128) != 0) ft_error();

        char *server_ip = get_local_ip();

		log_message("\t\t┏━━━━━━━━━━━━━━━ CHAT SERVER ━━━━━━━━━━━━━━━┓");
		log_message("\t\t┃                                           ┃");
		log_message("\t\t┃  🌐 Server Started Successfully           ┃");
		log_message("\t\t┃  📡 IP Address: %-15s           ┃", server_ip);
		log_message("\t\t┃  🔌 Port: %-22s          ┃", av[1]);
		log_message("\t\t┃                                           ┃");
		log_message("\t\t┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛");


        FD_SET(sockfd,&cur);
        int max = sockfd;
        int index = 0;
        while(1)
        {
            cur_read = cur_write = cur;
            if(select(max+1,&cur_read,&cur_write,NULL,NULL) < 0) continue;
            for(int fd = 0; fd <= max;fd++)
            {
                if(FD_ISSET(fd,&cur_read))
                {
                    if (fd == sockfd)
                    {
                        int newClient = accept(sockfd,NULL,NULL);
                        if (newClient <= 0) continue;
                        FD_SET(newClient,&cur);
                        client[newClient] = index++;
                        message[newClient] = malloc(1);
                        message[newClient][0] = 0;
                        if(newClient > max) max = newClient;
                        char str[100];
                        sprintf(str,"server: client %d just arrived\n",index-1);
                        ft_send(newClient,str);
                    }
                    else
                    {
                        char buffer[4095];
                        int lent = recv(fd,buffer,4094,0);
                        if(lent <= 0)
                        {
                            FD_CLR(fd,&cur);
                            char str[100];
                            sprintf(str,"server: client %d just left\n",client[fd]);
                            ft_send(fd,str);
                            client[fd] = -1;
                            close(fd);
                        }
                        else
                        {
                            buffer[lent] = 0;
                            message[fd] = str_join(message[fd],buffer);
                            char *tmp;
                            while(extract_message(&message[fd],&tmp))
                            {
                                char str[strlen(tmp) + 100];
                                sprintf(str,"client %d: %s",client[fd],tmp);
                                ft_send(fd,str);
                            }
                        }
                    }
                }
            }
        }
    }
    else
    {
        write(2, "Wrong number of arguments\n",strlen("Wrong number of arguments\n"));
        exit(1);
    }
}