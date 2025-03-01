#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

#define PORT_NUM 9000
#define BUFSIZE 512

int stop_flag;

void signal_handler(int signal_num);
int sendall(int s, char *buf, int *len);
void *response_handler(void *);

int main(int argc, char * argv[]){

	int sockfd, n, clientfd, client_sock, *new_sock;
	struct sockaddr_in serveraddr; /* server's addr */
  	struct sockaddr_in clientaddr; /* client addr */
  	struct hostent *hostp; /* client host info */
	char *hostaddrp;
	struct sigaction sa;
	stop_flag = 0;

	fflush(stdin);

	sa.sa_handler = signal_handler;

	if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("Error setting up SIGINT handler");
        return -1;
    }
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("Error setting up SIGTERM handler");
        return -1;
    }

	openlog("aesdsocket", LOG_PID, LOG_USER);

	if(argc == 1 || argc == 2){
		sockfd = socket(AF_INET, SOCK_STREAM, 0);

  		if (sockfd < 0){
			perror("ERROR opening socket");
			closelog();
			return -1;
		}

		bzero((char *) &serveraddr, sizeof(serveraddr));
		serveraddr.sin_family = AF_INET;
		serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
		serveraddr.sin_port = htons((unsigned short)PORT_NUM);

		if (bind(sockfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0){
    		perror("ERROR on binding");
			closelog();
			return -1;
		}

		if(argc == 2 && (strcmp(argv[1], "-d") == 0)){
			pid_t pid = fork();
			if (pid < 0) {
				perror("Fork failed");
				return -1;
			}
			if (pid > 0) {
				exit(0); 
			}

			if (setsid() < 0) {
				perror("Failed to create new session");
				return -1;
			}

			if (chdir("/") < 0) {
				perror("Failed to change directory");
				return -1;
			}

			close(STDIN_FILENO);  
			close(STDOUT_FILENO); 
			close(STDERR_FILENO); 

			int null_fd = open("/dev/null", O_RDWR);
			if (null_fd == -1) {
				perror("Failed to open /dev/null");
				return -1;
			}

			if (dup2(null_fd, STDIN_FILENO) == -1 ||
				dup2(null_fd, STDOUT_FILENO) == -1 ||
				dup2(null_fd, STDERR_FILENO) == -1) {
				perror("Failed to redirect file descriptors");
				return -1;
			}
		}

		int clientlen = sizeof(clientaddr);

		listen(sockfd , 3);
		
		int c = sizeof(struct sockaddr_in);

		while(1 && !stop_flag){
			
			while(client_sock = accept(sockfd, (struct sockaddr *)&clientaddr, (socklen_t*)&c)){

				hostaddrp = inet_ntoa(clientaddr.sin_addr);
				syslog(LOG_INFO, "Accepted connection from %s", hostaddrp);

				pthread_t sniffer_thread;
				new_sock = malloc(1);
				*new_sock = client_sock;

				if( pthread_create( &sniffer_thread , NULL ,  response_handler , (void*) new_sock) < 0)
				{
					perror("could not create thread");
				}
				if(pthread_detach(sniffer_thread) != 0){
					perror("Error detaching thread");
					return -1;
				}

			}

			

			//need to change this

			void * to_echo_back = malloc(file_size);

			if(to_echo_back == NULL){
				perror("malloc error");
				closelog();
				return -1;
			}

			int ret_val_read = read(fd, to_echo_back, file_size);
			
			if(ret_val_read == -1){
				perror("error with read");
				closelog();
				free(to_echo_back);
				return -1;
			}

			n = sendall(clientfd, to_echo_back, (int *)&file_size);
        	if (n < 0){
          		perror("ERROR in sendto");
				free(to_echo_back);
				closelog();
				return -1;
			}

			syslog(LOG_INFO, "Closed connection from %s", hostaddrp);
			free(to_echo_back);

		}

	}
	else{
		fprintf(stderr, "There was an issue with arguments.\nfunction usage: ./aesdsocket or ./aesdsocket -d\n");
		closelog();
		return -1;
	}
	closelog();
	return 0;

}

void *response_handler(void *socket_desc){

	char buf[BUFSIZE];
	int sock = *(int*)socket_desc;
	int n;
	char *token;
	int found_terminator;

	int fd = open("/var/tmp/aesdsocketdata", O_CREAT|O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	if(fd == -1){
		perror("error with open");
		closelog();
		close(sock);
		return NULL;
	}

	while(1){
		bzero(buf, BUFSIZE);
		n = recv(sock, buf, BUFSIZE, 0);
		if (n < 0){
			perror("ERROR in recv");
			closelog();
			close(sock);
			return NULL;
		}
		printf("read: %d bytes\n", n);
		
		found_terminator = 0;

		for(int i = 0; i < n; i++){
			if(buf[i] == '\n'){
				found_terminator = 1;
			}
		}

		if((token = strtok(buf, "\n")) == NULL){
			fprintf(stderr, "Ran into issues with finding a full packet\n");
			closelog();
			close(sock);
			return NULL;
		}

		lseek(fd, 0, SEEK_END);

		int len_to_write = strlen(token);

		if(write(fd, token, len_to_write) != len_to_write){
			fprintf(stderr, "Ran into issues with sending a full packet\n");
			closelog();
			return -1;
		}

		if(found_terminator) break;

	}

	write(fd, "\n", 1);

	lseek(fd, 0, SEEK_SET);

	struct stat file_stat;
	fstat(fd, &file_stat);
	off_t file_size = file_stat.st_size;

}

void signal_handler(int signal_num) {
    syslog(LOG_INFO, "Caught signal, exiting\n");
	//I don't think there is contention over this stop flag.
    stop_flag = 1;
	system("rm -f /var/tmp/aesdsocketdata");
	return;
}

int sendall(int s, char *buf, int *len)
{
    int total = 0;       
    int bytesleft = *len; 
    int n;

    while(total < *len) {
        n = send(s, buf+total, bytesleft, 0);
        if (n == -1) { break; }
        total += n;
        bytesleft -= n;
    }

    *len = total; 

    return n==-1?-1:0; 
}