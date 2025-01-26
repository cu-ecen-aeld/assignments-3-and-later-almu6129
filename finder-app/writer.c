#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>

#define INTENDED_NUM_ARGS 3u

int main(int argc, char * argv[]){

	openlog("writer log", LOG_NDELAY, LOG_USER);

	if(argc != INTENDED_NUM_ARGS){
		syslog(LOG_ERR, "There was an issue with the command arguments.");
		printf("There was an issue with the command arguments.\r\n");
		printf("To run, type: ./writer <filename> <string to write>\r\n");
		return 1;
	}

	char * file_name = argv[1];

	FILE * file_descriptor = fopen(file_name, "w");

	if(file_descriptor == NULL){
		syslog(LOG_ERR, "There was an issue opening the file.");
		printf("There was an issue opening the file\r\n");
		printf("Please double check the directory was created.\r\n");
		return 1;
	}

	syslog(LOG_DEBUG, "Writing %s to %s", argv[2], argv[1]);
	fprintf(file_descriptor, "%s", argv[2]);

	fclose(file_descriptor);
	closelog();

	return 0;

}
