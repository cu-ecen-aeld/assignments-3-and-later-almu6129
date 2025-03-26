#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <stdbool.h>
#include "../aesd-char-driver/aesd_ioctl.h"

#include "queue.h"

#define PORT_NUM 9000
#define BUFSIZE 512
#define SEEKTO_LETTER_LEN 19

#define USE_AESD_CHAR_DEVICE 1

#ifdef USE_AESD_CHAR_DEVICE
	#define FILE_LOCATION "/dev/aesdchar"
#else
	#define FILE_LOCATION "/var/tmp/aesdsocketdata"
#endif

struct thread_context_t
{
	char ip_add[30];
	int new_sock;
	//shared pointer to the lock
	pthread_mutex_t *file_mutex_lock;
	pthread_t sniffer_thread;

};

typedef struct thread_context_t thread_context;

struct node
{
    thread_context *thread_info;
    TAILQ_ENTRY(node) nodes;
};


typedef TAILQ_HEAD(head_s, node) head_t;

int stop_flag;
pthread_mutex_t *list_mutex_lock;

void signal_handler(int signal_num);
int sendall(int s, char *buf, int *len);
void *response_handler(void *);
void *joiner_handler(void *);
void *timer_handler(void *);

int main(int argc, char * argv[]){

	int sockfd, n, clientfd, client_sock;
	struct sockaddr_in serveraddr; /* server's addr */
  	struct sockaddr_in clientaddr; /* client addr */
  	struct hostent *hostp; /* client host info */
	char *hostaddrp;
	struct sigaction sa;
	stop_flag = 0;
	pthread_t garbage_collector_thread;

	#ifndef USE_AESD_CHAR_DEVICE
	pthread_t timer_thread;
	#endif

	pthread_mutex_t file_mutex;
	pthread_mutex_init(&file_mutex, NULL);

	pthread_mutex_t list_mutex;
	pthread_mutex_init(&list_mutex, NULL);

	list_mutex_lock = &list_mutex;

	head_t head;
    TAILQ_INIT(&head);

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
				return 0; 
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

		if( pthread_create( &garbage_collector_thread , NULL ,  joiner_handler , (void*) &head) < 0)
		{
			perror("could not create thread");
			return -1;
		}

		#ifndef USE_AESD_CHAR_DEVICE
		thread_context * timer_thread_info = (thread_context *)malloc(sizeof(thread_context));

		if(timer_thread_info == NULL){
			perror("error with malloc");
			return -1;
		}

		timer_thread_info -> file_mutex_lock = &file_mutex;

		if( pthread_create( &timer_thread , NULL ,  timer_handler , (void*) timer_thread_info) < 0)
		{
			perror("could not create thread");
			return -1;
		}
		#endif
		int c = sizeof(struct sockaddr_in);

		while(1 && !stop_flag){
			
			while((client_sock = accept(sockfd, (struct sockaddr *)&clientaddr, (socklen_t*)&c)) && !stop_flag){

				hostaddrp = inet_ntoa(clientaddr.sin_addr);
				syslog(LOG_INFO, "Accepted connection from %s", hostaddrp);

				thread_context * thread_info = (thread_context *)malloc(sizeof(thread_context));

				if(thread_info == NULL){
					perror("error with malloc");
					return -1;
				}

				thread_info -> file_mutex_lock = &file_mutex;
				thread_info -> new_sock = client_sock;
				strncpy(thread_info -> ip_add, hostaddrp, strlen(hostaddrp));

				if( pthread_create( &thread_info -> sniffer_thread , NULL ,  response_handler , (void*) thread_info) < 0)
				{
					perror("could not create thread");
					return -1;
				}
				
				struct node * e = malloc(sizeof(struct node));

				if(e == NULL){
					perror("error with malloc");
					return -1;
				}

				e -> thread_info = thread_info;

				pthread_mutex_lock(list_mutex_lock);
				TAILQ_INSERT_TAIL(&head, e, nodes);
				pthread_mutex_unlock(list_mutex_lock);

			}
		}

	}
	else{
		fprintf(stderr, "There was an issue with arguments.\nfunction usage: ./aesdsocket or ./aesdsocket -d\n");
		closelog();
		return -1;
	}

	pthread_join(garbage_collector_thread, NULL);
	#ifndef USE_AESD_CHAR_DEVICE
	pthread_cancel(timer_thread);
	#endif

	closelog();

	return 0;

}

void *response_handler(void *thread_info){

	char buf[BUFSIZE];
	thread_context * total_context = (thread_context *)thread_info;
	int n;
	char *token;
	int found_terminator;
	int bytes_read;

	int fd = open(FILE_LOCATION, O_CREAT|O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	if(fd == -1){
		perror("error with open");
		return thread_info;
	}

	while(1){
		bzero(buf, BUFSIZE);
		n = recv(total_context -> new_sock, buf, BUFSIZE, 0);
		if (n < 0){
			perror("ERROR in recv");
			return thread_info;
		}
		
		found_terminator = 0;

		for(int i = 0; i < n; i++){
			if(buf[i] == '\n'){
				found_terminator = 1;
			}
		}

		if((token = strtok(buf, "\n")) == NULL){
			fprintf(stderr, "Ran into issues with finding a full packet\n");
			return thread_info;
		}

		pthread_mutex_lock(total_context -> file_mutex_lock);

		if(strstr(token, "AESDCHAR_IOCSEEKTO:") == NULL){
			lseek(fd, 0, SEEK_END);
		}
		else{
			struct aesd_seekto seek_struct;
			int x, y;
			openlog(NULL, LOG_CONS, LOG_USER);
			if(sscanf(token, "AESDCHAR_IOCSEEKTO:%d,%d", &x, &y) != 2){
				fprintf(stderr, "Ran into issues parsing the seekto command\n");
				syslog(LOG_DEBUG, "Ran into issues parsing the string");
				pthread_mutex_unlock(total_context -> file_mutex_lock);
				closelog();
				return thread_info;
			}
			syslog(LOG_DEBUG, "Seeking to command: %d at offset %d", x, y);
			seek_struct.write_cmd = x;
			seek_struct.write_cmd_offset = y;

			ioctl(fd, AESDCHAR_IOCSEEKTO, seek_struct);

			pthread_mutex_unlock(total_context -> file_mutex_lock);
			closelog();
			found_terminator = 0;
			continue;
		}

		int len_to_write = strlen(token);

		if(write(fd, token, len_to_write) != len_to_write){
			fprintf(stderr, "Ran into issues with sending a full packet\n");
			pthread_mutex_unlock(total_context -> file_mutex_lock);
			return thread_info;
		}
		pthread_mutex_unlock(total_context -> file_mutex_lock);

		if(found_terminator) break;

	}

	pthread_mutex_lock(total_context -> file_mutex_lock);

	write(fd, "\n", 1);

	//Shouldn't seek to the beggining anymore for the readback I believe
	//lseek(fd, 0, SEEK_SET);

	while ((bytes_read = read(fd, buf, BUFSIZE)) > 0) {
		sendall(total_context -> new_sock, buf, &bytes_read);
    }

	pthread_mutex_unlock(total_context -> file_mutex_lock);

	if (bytes_read == -1){
        perror("Error reading file");
        close(fd);
        return thread_info;
    }

	close(fd);
	return thread_info;
}

void *joiner_handler(void *arr){

	head_t * head = (head_t *)arr;
	struct node * e = NULL;
	struct node * next = NULL;

	while(!stop_flag){

		pthread_mutex_lock(list_mutex_lock);

		if(!TAILQ_EMPTY(head)){

			TAILQ_FOREACH_SAFE(e, head, nodes, next)
			{
				if(pthread_tryjoin_np(e->thread_info->sniffer_thread, NULL) == 0){

					syslog(LOG_INFO, "Closed connection from %s", e->thread_info->ip_add);
					TAILQ_REMOVE(head, e, nodes);
					free(e -> thread_info);
					free(e);
					e = NULL;
				}
			}
		}

		pthread_mutex_unlock(list_mutex_lock);
		//periodically examine the list
		usleep(200000);
	}
}

#ifndef USE_AESD_CHAR_DEVICE
void *timer_handler(void *thread_info){

	thread_context * total_context = (thread_context *)thread_info;
	time_t rawtime;
    struct tm *timeinfo;
    char time_str[100];

	int fd = open("/var/tmp/aesdsocketdata", O_CREAT|O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	if(fd == -1){
		perror("error with open");
		return thread_info;
	}

	while(!stop_flag){

		sleep(10);

		tzset();
		time(&rawtime);
    	timeinfo = localtime(&rawtime);

		strftime(time_str, sizeof(time_str), "timestamp:%a, %d %b %Y %H:%M:%S %z\n", timeinfo);

		int len_to_write = strlen(time_str);

		pthread_mutex_lock(total_context -> file_mutex_lock);

		lseek(fd, 0, SEEK_END);
		if(write(fd, time_str, len_to_write) != len_to_write){
			fprintf(stderr, "Ran into issues with sending a full packet\n");
			pthread_mutex_unlock(total_context -> file_mutex_lock);
			return thread_info;
		}
		pthread_mutex_unlock(total_context -> file_mutex_lock);
	}

	close(fd);

}
#endif

void signal_handler(int signal_num) {
    syslog(LOG_INFO, "Caught signal, exiting\n");
	//I don't think there is contention over this stop flag.
    stop_flag = 1;
	#ifndef USE_AESD_CHAR_DEVICE
	system("rm -f /var/tmp/aesdsocketdata");
	#endif
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
