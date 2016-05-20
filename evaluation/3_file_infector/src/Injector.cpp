#include "Injector.h"
#include <stdio.h>

//Assumes malloc won't fail
pfile_info file_info_create(void) {
    pfile_info mapped_file_info = (pfile_info)malloc(sizeof(file_info));
    memset(mapped_file_info, 0, sizeof(file_info));
    return mapped_file_info;
}

//Assumes everything is valid, doesn't report error code
void file_info_destroy(pfile_info mapped_file_info) {
    if(mapped_file_info->file_mem_buffer != NULL)
        UnmapViewOfFile(mapped_file_info->file_mem_buffer);
    if(mapped_file_info->file_handle != NULL)
        CloseHandle(mapped_file_info->file_handle);
    if(mapped_file_info->file_map_handle != NULL)
        CloseHandle(mapped_file_info->file_map_handle);
    free(mapped_file_info);
    mapped_file_info = NULL;
}

inline unsigned int align_to_boundary(unsigned int address, unsigned int boundary) {
	return (((address + boundary - 1) / boundary) * boundary);
}
unsigned int get_stub_size(void* stub_addr) {
    unsigned int size = 0;
    if(stub_addr != NULL) {
        const char *stub_signature = "\xCC\xCC\xCC\xCC";
        while(memcmp(((unsigned char *)stub_addr + size), stub_signature, sizeof(int)) != 0)
            ++size;
    }
    return size;
}

bool map_file(const wchar_t *file_name, unsigned int stub_size, bool append_mode, pfile_info mapped_file_info) {
    void *file_handle = CreateFile(file_name, GENERIC_READ | GENERIC_WRITE, 0,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(file_handle == INVALID_HANDLE_VALUE) {
        wprintf(L"Could not open %s", file_name);
        return false;
    }
    unsigned int file_size = GetFileSize(file_handle, NULL);
    if(file_size == INVALID_FILE_SIZE) {
        wprintf(L"Could not get file size for %s", file_name);
        return false;
    }
    if(append_mode == true) {
        file_size += (stub_size + sizeof(DWORD_PTR));
    }
    void *file_map_handle = CreateFileMapping(file_handle, NULL, PAGE_READWRITE, 0,
        file_size, NULL);
    if(file_map_handle == NULL) {
        wprintf(L"File map could not be opened");
        CloseHandle(file_handle);
        return false;
    }
    void *file_mem_buffer = MapViewOfFile(file_map_handle, FILE_MAP_WRITE, 0, 0, file_size);
    if(file_mem_buffer == NULL) {
        wprintf(L"Could not map view of file");
        CloseHandle(file_map_handle);
        CloseHandle(file_handle);
        return false;
    }
    mapped_file_info->file_handle = file_handle;
    mapped_file_info->file_map_handle = file_map_handle;
    mapped_file_info->file_mem_buffer = (unsigned char*)file_mem_buffer;
    return true;
}

//Reference: http://www.codeproject.com/KB/system/inject2exe.aspx
PIMAGE_SECTION_HEADER add_section(const char *section_name, unsigned int section_size, void *image_addr) {
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)image_addr;
    if(dos_header->e_magic != 0x5A4D) {
        wprintf(L"Could not retrieve DOS header from %p", image_addr);
        return NULL;
    }
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)dos_header + dos_header->e_lfanew);
    if(nt_headers->OptionalHeader.Magic != 0x010B) {
        wprintf(L"Could not retrieve NT header from %p", dos_header);
        return NULL;
    }
    const int name_max_length = 8;
    PIMAGE_SECTION_HEADER last_section = IMAGE_FIRST_SECTION(nt_headers) + (nt_headers->FileHeader.NumberOfSections - 1);
    PIMAGE_SECTION_HEADER new_section = IMAGE_FIRST_SECTION(nt_headers) + (nt_headers->FileHeader.NumberOfSections);
    memset(new_section, 0, sizeof(IMAGE_SECTION_HEADER));
    new_section->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
    memcpy(new_section->Name, section_name, name_max_length);
    new_section->Misc.VirtualSize = section_size;
    new_section->PointerToRawData = align_to_boundary(last_section->PointerToRawData + last_section->SizeOfRawData,
        nt_headers->OptionalHeader.FileAlignment);
    new_section->SizeOfRawData = align_to_boundary(section_size, nt_headers->OptionalHeader.SectionAlignment);
    new_section->VirtualAddress = align_to_boundary(last_section->VirtualAddress + last_section->Misc.VirtualSize,
        nt_headers->OptionalHeader.SectionAlignment);
    nt_headers->OptionalHeader.SizeOfImage =  new_section->VirtualAddress + new_section->Misc.VirtualSize;
    nt_headers->FileHeader.NumberOfSections++;
    return new_section;
}

void copy_stub_instructions(PIMAGE_SECTION_HEADER section, void *image_addr, void *stub_addr) {
    unsigned int stub_size = get_stub_size(stub_addr);
    memcpy(((unsigned char *)image_addr + section->PointerToRawData), stub_addr, stub_size);
}

void change_file_oep(PIMAGE_NT_HEADERS nt_headers, PIMAGE_SECTION_HEADER section) {
    unsigned int file_address = section->PointerToRawData;
    PIMAGE_SECTION_HEADER current_section = IMAGE_FIRST_SECTION(nt_headers);
    for(int i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
        if(file_address >= current_section->PointerToRawData &&
            file_address < (current_section->PointerToRawData + current_section->SizeOfRawData)){
                file_address -= current_section->PointerToRawData;
                file_address += (nt_headers->OptionalHeader.ImageBase + current_section->VirtualAddress);
                break;
        }
    ++current_section;
    }
    nt_headers->OptionalHeader.AddressOfEntryPoint =  file_address - nt_headers->OptionalHeader.ImageBase;
}

void write_stub_entry_point(PIMAGE_NT_HEADERS nt_headers, void *stub_addr) {
    if(stub_addr != NULL) {
        const char *signature = "\xFF\xEE\xDD\xCC";
        unsigned int index = 0;
        while(memcmp(((unsigned char *)stub_addr + index), signature, sizeof(int)) != 0) {
            ++index;
        }
        DWORD old_protections = 0;
        VirtualProtect(((unsigned char *)stub_addr + index), sizeof(DWORD), PAGE_EXECUTE_READWRITE, &old_protections);
        memcpy(((unsigned char *)stub_addr + index), &nt_headers->OptionalHeader.AddressOfEntryPoint, sizeof(DWORD));
        VirtualProtect(((unsigned char *)stub_addr + index), sizeof(DWORD), old_protections, NULL);
    }
}