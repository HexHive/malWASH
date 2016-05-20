#include <Windows.h>
#include <wchar.h>
#include <stdio.h>
#include "Injector.h"
#include "Encrypter.h"

#define BB(x) __asm _emit x

#define STRING_COMPARE(str1, str2) \
    __asm push str1 \
    __asm call get_string_length \
    __asm push eax \
    __asm push str1 \
    __asm mov eax, str2 \
    __asm push eax \
    __asm call strings_equal

#pragma code_seg(".inject")
void __declspec(naked) injection_stub(void) {
    __asm { //Prologue, stub entry point
        pushad                  //Save context of entry point
        push ebp                //Set up stack frame
        mov ebp, esp
        sub esp, 0x200          //Space for local variables

    }
    PIMAGE_DOS_HEADER target_image_base;
    PIMAGE_DOS_HEADER kernel32_image_base;
    __asm {
        call get_module_list    //Get PEB
        mov ebx, eax
        push 0
        push ebx
        call get_dll_base       //Get image base of process
        mov [target_image_base], eax
        push 2
        push ebx
        call get_dll_base       //Get kernel32.dll image base
        mov [kernel32_image_base], eax
    }
    __asm { //Decrypt all sections
        push kernel32_image_base
        push target_image_base
        call decrypt_sections
    }
    //Any additional code can go here
    __asm { //Epilogue, stub exit point
        mov eax, target_image_base
        add eax, 0xCCDDEEFF     //Signature to be replaced by original entry point (OEP)
        mov esp, ebp
        mov [esp+0x20], eax     //Store OEP in EAX through ESP to preserve across popad
        pop ebp
        popad                   //Restore thread context, with OEP in EAX
        jmp eax                 //Jump to OEP
    }

    ///////////////////////////////////////////////////////////////////
    //Gets the module list
    //Preserves no registers, PEB_LDR_DATA->PPEB_LDR_DATA->InLoadOrderModuleList returned in EAX
    ///////////////////////////////////////////////////////////////////
    __asm {
    get_module_list:       
            mov eax, fs:[0x30]  //PEB
            mov eax, [eax+0xC]  //PEB_LDR_DATA->PPEB_LDR_DATA
            mov eax, [eax+0xC]  //PEB_LDR_DATA->PPEB_LDR_DATA->InLoadOrderModuleList
            retn
    }
    ///////////////////////////////////////////////////////////////////

    ///////////////////////////////////////////////////////////////////
    //Gets the DllBase member of the InLoadOrderModuleList structure
    //Call as void *get_dll_base(void *InLoadOrderModuleList, int index)
    ///////////////////////////////////////////////////////////////////
    __asm {
    get_dll_base:
        push ebp
        mov ebp, esp
        cmp [ebp+0xC], 0x0      //Initial zero check
        je done
        mov ecx, [ebp+0xC]      //Set loop index
        mov eax, [ebp+0x8]      //PEB->PPEB_LDR_DATA->InLoadOrderModuleList address
        traverse_list:
            mov eax, [eax]      //Go to next entry
        loop traverse_list
        done:
            mov eax, [eax+0x18] //PEB->PPEB_LDR_DATA->InLoadOrderModuleList.DllBase
            mov esp, ebp
            pop ebp
            ret 0x8
    }
    ///////////////////////////////////////////////////////////////////

    ///////////////////////////////////////////////////////////////////
    //Gets the length of the string passed as the parameter
    //Call as int get_string_length(char *str)
    ///////////////////////////////////////////////////////////////////
    __asm {
    get_string_length:
        push ebp
        mov ebp, esp
        mov edi, [ebp+0x8]      //String held here
        mov eax, 0x0            //EAX holds size of the string
        counting_loop:
            cmp byte ptr[edi], 0x0//Current byte is null-terminator?
            je string_done      //Done, leave loop
            inc edi             //Go to next character
            inc eax             //size++
            jmp counting_loop
        string_done:
            mov esp, ebp
            pop ebp
            retn
    }
    ///////////////////////////////////////////////////////////////////

    ///////////////////////////////////////////////////////////////////
    //String comparison function, checks for equality of two strings
    //Call as bool strings_equal(char *check_string, char *known_string, int known_string_length)
    ///////////////////////////////////////////////////////////////////
    __asm {
    strings_equal:
        push ebp
        mov ebp, esp
        mov eax, 0x0            //Assume unequal
        cld                     //Forward comparison
        mov esi, [ebp+0x8]      //ESI gets check_string
        mov edi, [ebp+0xC]      //EDI gets known_string
        mov ecx, [ebp+0x10]     //ECX gets known_string_length
        repe cmpsb              //Start comparing
        jne end
        mov eax, 0x1            //Strings equal
    end:
        mov esp, ebp
        pop ebp
        ret 0xC
    }
    ///////////////////////////////////////////////////////////////////

    ///////////////////////////////////////////////////////////////////
    //Implementation of GetProcAddress
    //Call as FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
    ///////////////////////////////////////////////////////////////////
    get_proc_address:
        __asm {
            push ebp
            mov ebp, esp
            sub esp, 0x200
        }
        PIMAGE_DOS_HEADER kernel32_dos_header;
        PIMAGE_NT_HEADERS kernel32_nt_headers;
        PIMAGE_EXPORT_DIRECTORY kernel32_export_dir;
        unsigned short *ordinal_table;
        unsigned long *function_table;
        FARPROC function_address;
        int function_names_equal;
        __asm { //Initializations
            mov eax, [ebp+0x8]
            mov kernel32_dos_header, eax
            mov function_names_equal, 0x0
        }
        kernel32_nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)kernel32_dos_header + kernel32_dos_header->e_lfanew);
        kernel32_export_dir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)kernel32_dos_header + 
            kernel32_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        for(unsigned long i = 0; i < kernel32_export_dir->NumberOfNames; ++i) {
            char *eat_entry = (*(char **)((DWORD_PTR)kernel32_dos_header + kernel32_export_dir->AddressOfNames + i * sizeof(DWORD_PTR)))
                + (DWORD_PTR)kernel32_dos_header;   //Current name in name table
            STRING_COMPARE([ebp+0xC], eat_entry) //Compare function in name table with the one we want to find
            __asm mov function_names_equal, eax
            if(function_names_equal == 1) {
                ordinal_table = (unsigned short *)(kernel32_export_dir->AddressOfNameOrdinals + (DWORD_PTR)kernel32_dos_header);
                function_table = (unsigned long *)(kernel32_export_dir->AddressOfFunctions + (DWORD_PTR)kernel32_dos_header);
                function_address = (FARPROC)((DWORD_PTR)kernel32_dos_header + function_table[ordinal_table[i]]);
                break;
            }
        }
        __asm {
            mov eax, function_address
            mov esp, ebp
            pop ebp
            ret 0x8
        }
    ///////////////////////////////////////////////////////////////////
    
    ///////////////////////////////////////////////////////////////////
    //Decrypts all sections in the image, excluding .rdata/.rsrc/.inject
    //Call as void decrypt_sections(void *image_base, void *kernel32_base)
    ///////////////////////////////////////////////////////////////////
    decrypt_sections:
        __asm {
            push ebp
            mov ebp, esp
            sub esp, 0x200
        }
        typedef BOOL (WINAPI *pVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect,
            PDWORD lpflOldProtect);
        char *str_virtualprotect;
        char *str_section_name;
        char *str_rdata_name;
        char *str_rsrc_name;
        PIMAGE_DOS_HEADER target_dos_header;
        int section_offset;
        int section_names_equal;
        unsigned long old_protections;
        pVirtualProtect virtualprotect_addr;
        __asm { //String initializations
            jmp virtualprotect
            virtualprotectback:
                pop esi
                mov str_virtualprotect, esi
            jmp section_name
            section_nameback:
                pop esi
                mov str_section_name, esi
            jmp rdata_name
            rdata_nameback:
                pop esi
                mov str_rdata_name, esi
            jmp rsrc_name
            rsrc_nameback:
                pop esi
                mov str_rsrc_name, esi
        }
        __asm { //Initializations
            mov eax, [ebp+0x8]
            mov target_dos_header, eax
            mov section_offset, 0x0
            mov section_names_equal, 0x0
            push str_virtualprotect
            push [ebp+0xC]
            call get_proc_address
            mov virtualprotect_addr, eax
        }
        PIMAGE_NT_HEADERS target_nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)target_dos_header + target_dos_header->e_lfanew);
        for(unsigned long j = 0; j < target_nt_headers->FileHeader.NumberOfSections; ++j) {
            section_offset = (target_dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS) +
                (sizeof(IMAGE_SECTION_HEADER) * j));
            PIMAGE_SECTION_HEADER section_header = (PIMAGE_SECTION_HEADER)((DWORD_PTR)target_dos_header + section_offset);
            STRING_COMPARE(str_section_name, section_header)
            __asm mov section_names_equal, eax
            STRING_COMPARE(str_rdata_name, section_header)
            __asm add section_names_equal, eax
            STRING_COMPARE(str_rsrc_name, section_header)
            __asm add section_names_equal, eax
            if(section_names_equal == 0) {
                unsigned char *current_byte = 
                    (unsigned char *)((DWORD_PTR)target_dos_header + section_header->VirtualAddress);
                unsigned char *last_byte = 
                    (unsigned char *)((DWORD_PTR)target_dos_header + section_header->VirtualAddress 
                    + section_header->SizeOfRawData);
                const unsigned int num_rounds = 32;
                const unsigned int key[4] = {0x12345678, 0xAABBCCDD, 0x10101010, 0xF00DBABE};
                for(current_byte; current_byte < last_byte; current_byte += 8) {
                    virtualprotect_addr(current_byte, sizeof(DWORD_PTR) * 2, PAGE_EXECUTE_READWRITE, &old_protections);
                    unsigned int block1 = (*current_byte << 24) | (*(current_byte+1) << 16) |
                        (*(current_byte+2) << 8) | *(current_byte+3);
                    unsigned int block2 = (*(current_byte+4) << 24) | (*(current_byte+5) << 16) |
                        (*(current_byte+6) << 8) | *(current_byte+7);
                    unsigned int full_block[] = {block1, block2};
                    unsigned int delta = 0x9E3779B9;
                    unsigned int sum = (delta * num_rounds);
                    for (unsigned int i = 0; i < num_rounds; ++i) {
                        full_block[1] -= (((full_block[0] << 4) ^ (full_block[0] >> 5)) + full_block[0]) ^ (sum + key[(sum >> 11) & 3]);
                        sum -= delta;
                        full_block[0] -= (((full_block[1] << 4) ^ (full_block[1] >> 5)) + full_block[1]) ^ (sum + key[sum & 3]);
                    }
                    virtualprotect_addr(current_byte, sizeof(DWORD_PTR) * 2, old_protections, NULL);
                    *(current_byte+3) = (full_block[0] & 0x000000FF);
                    *(current_byte+2) = (full_block[0] & 0x0000FF00) >> 8;
                    *(current_byte+1) = (full_block[0] & 0x00FF0000) >> 16;
                    *(current_byte+0) = (full_block[0] & 0xFF000000) >> 24;
                    *(current_byte+7) = (full_block[1] & 0x000000FF);
                    *(current_byte+6) = (full_block[1] & 0x0000FF00) >> 8;
                    *(current_byte+5) = (full_block[1] & 0x00FF0000) >> 16;
                    *(current_byte+4) = (full_block[1] & 0xFF000000) >> 24;
                }
            }
            section_names_equal = 0;
        }
        __asm {
            mov esp, ebp
            pop ebp
            ret 0x8
        }

    __asm {
    virtualprotect:
        call virtualprotectback
        BB('V') BB('i') BB('r') BB('t') BB('u') BB('a') BB('l')
        BB('P') BB('r') BB('o') BB('t') BB('e') BB('c') BB('t') BB(0)
    rdata_name:
        call rdata_nameback
        BB('.') BB('r') BB('d') BB('a') BB('t') BB('a') BB(0)
    rsrc_name:
        call rsrc_nameback
        BB('.') BB('r') BB('s') BB('r') BB('c') BB(0)
    section_name:
        call section_nameback
        BB('.') BB('i') BB('n') BB('j') BB('e') BB('c') BB('t') BB(0)
        int 0x3                 //Function signature
        int 0x3
        int 0x3
        int 0x3
    }
}
#pragma code_seg()
#pragma comment(linker, "/SECTION:.inject,re")

wchar_t *convert_to_unicode(char *str, unsigned int length) {
    wchar_t *wstr;
    int wstr_length = MultiByteToWideChar(CP_ACP, 0, str, (length + 1), NULL, 0);
    wstr = (wchar_t *)malloc(wstr_length * sizeof(wchar_t));
    wmemset(wstr, 0, wstr_length);
    if (wstr == NULL)
        return NULL;
    int written = MultiByteToWideChar(CP_ACP, 0, str, length, wstr, wstr_length);
    if(written > 0)
        return wstr;
    return NULL;
}

int main(int argc, char* argv[]) {
    if(argc != 2) {
        printf("Usage: ./%s <target>\n", argv[0]);
        return -1;
    }
    wchar_t *target_file_name = convert_to_unicode(argv[1], strlen(argv[1]));
    if(target_file_name == NULL) {
        printf("Could not convert %s to unicode\n", argv[1]);
        return -1;
    }
    pfile_info target_file = file_info_create();
    void (*stub_addr)(void) = injection_stub;
    unsigned int stub_size = get_stub_size(stub_addr);
    unsigned int stub_size_aligned = 0;
    bool map_file_success = map_file(target_file_name, stub_size, false, target_file);
    if(map_file_success == false) {
        wprintf(L"Could not map target file\n");
        return -1;
    }
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)target_file->file_mem_buffer;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)dos_header + dos_header->e_lfanew);
    stub_size_aligned = align_to_boundary(stub_size, nt_headers->OptionalHeader.SectionAlignment);
    const char *section_name = ".inject";
    file_info_destroy(target_file);
    target_file = file_info_create();
    (void)map_file(target_file_name, stub_size_aligned, true, target_file);
    PIMAGE_SECTION_HEADER new_section = add_section(section_name, stub_size_aligned, target_file->file_mem_buffer);
    if(new_section == NULL) {
        wprintf(L"Could not add new section to file");
        return -1;
    }
    write_stub_entry_point(nt_headers, stub_addr);
    copy_stub_instructions(new_section, target_file->file_mem_buffer, stub_addr);
    change_file_oep(nt_headers, new_section);
    encrypt_file(nt_headers, target_file, section_name);
    int flush_view_success = FlushViewOfFile(target_file->file_mem_buffer, 0);
    if(flush_view_success == 0)
        wprintf(L"Could not save changes to file");
    file_info_destroy(target_file);
    return 0;
}