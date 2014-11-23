//*****************************************************
//*****************************************************
//
// mpctl.c 
// Project: mptcp_proxy
//
//*****************************************************
//*****************************************************
//
// GEORG HAMPEL - Bell Labs/NJ/USA: All Rights Reserved
//
//*****************************************************
//*****************************************************
//*****************************************************

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#define LEN_FIFO_MSG 1000

#include "common.h"

void writehelp() {
	printf("Command syntax:\n");
	printf(" -L                       list all sessions and subflows\n");
	printf("      -sess [SESS_ID]       session id, default = all sessions\n");
	printf(" -A                       add subflow\n");
	printf("      -sess [SESS_ID]       session id, default = highest SESS_ID\n");
	printf("      -ipl  [IP_LOCAL]      local ip, default = local IP of 1st subflow\n");
	printf("      -ipr  [IP_REMOTE]     remote ip, default = remote IP of 1st subflow\n");
	printf("      -ptl  [PRT_LOCAL]     local port, default = random port\n");
	printf("      -ptr  [PRT_REMOTE]    remote port, default = remote port of 1st subflow\n");
	printf("      -if   [IF_LOCAL]      adds one subflow from IF_LOCAL for SESS_ID - overwrites -ipl specification\n");
	printf(" -D                       delete subflow\n");
	printf("      -sess [SESS_ID]       session id, default = highest SESS_ID\n");
	printf("      -sfl  [SFL_ID]        subflow id, default = highest candidate subflow\n");
	printf(" -S                       switch subflows\n");
	printf("      -sess [SESS_ID]       session id, default = highest SESS_ID\n");
	printf("      -sfl  [SFL_ID]        subflow id of new active subflow, default = highest candidate\n");
	printf(" -B                       break subflow\n");
	printf("      -sess [SESS_ID]       session id, default = highest SESS_ID\n");
	printf("      -sfl  [SFL_ID]        subflow id candidate subflow, default = highest candidate\n");
	printf(" start/stop                start/stop mptcp_proxy\n");
}



int main(int argc, char **argv)
{
	//deal with commandline arguments
	char incmd[200];


	//analyze commandline args
	if( (argc<2) || strcmp(argv[1],"-help")==0 || strcmp(argv[1],"--help")==0  ) {
		printf("argc=%d\n", argc);
		writehelp();
		exit(0);
	}
	int i;
	strcpy(incmd, argv[1]);
	if( strcmp(argv[1], "stop")==0) strcpy(incmd, "-Q");
	for(i=2; i<argc; i++) {
		strcat(incmd," ");
		strcat(incmd,argv[i]);
	}

	if(argc > 1 && strcmp(argv[1], "start")==0) system("mptcp_proxy &");

	//make down FIFO
	mkfifo(FIFO_NAME_DOWN, (mode_t) 0666);

	//open fifo
	int fd_down = open(FIFO_NAME_DOWN, O_WRONLY | O_NONBLOCK);

	//send data
	int ret = write(fd_down, incmd, strlen(incmd));
	if(ret < -1){
		printf("mpproxy: writing to pipe failed\n");
		exit(0);
	}
	close(fd_down);


	//make up FIFO
	mkfifo(FIFO_NAME_UP, (mode_t) 0666);

	//open fifo
	int fd_up = open(FIFO_NAME_UP, O_RDONLY | O_NONBLOCK);

	fd_set fds_test;
	fd_set fds_input;
	FD_ZERO(&fds_input);		 
	FD_SET(fd_up, &fds_input);
	fds_test = fds_input;
	struct timeval timeout;
	timeout.tv_sec = 1; 
	timeout.tv_usec = 0;

	char buf[LEN_FIFO_MSG+1];
	int fd;
	int rtn = select(FD_SETSIZE, &fds_test, (fd_set *) NULL, (fd_set *) NULL, &timeout);
	if(rtn == -1) {
		printf("mpproxy: select returns=%d, exit program!\n",rtn);	
		exit(1);
	}
	
	for(fd = 0; fd < FD_SETSIZE; fd++){
		if(FD_ISSET(fd, &fds_test)){

			if (fd == fd_up){
				ret = read(fd_up, buf, LEN_FIFO_MSG);
				buf[ret] = '\0';
				if(ret < -1){
					printf("mpproxy: reading from pipe failed\n");
					close(fd_up);
					exit(0);
				}
				close(fd_up);
				if(buf[0] != '\0') printf("%s\n", buf);
			}
		}//end if F
	}
} 
