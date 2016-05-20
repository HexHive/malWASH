#pragma once
#include <Windows.h>

typedef struct {
    void *file_handle;
    void *file_map_handle;
    unsigned char *file_mem_buffer;
} file_info, *pfile_info;

pfile_info file_info_create(void);
void file_info_destroy(pfile_info mapped_file_info);
unsigned int align_to_boundary(unsigned int address, unsigned int boundary);
unsigned int get_stub_size(void* stub_addr);
bool map_file(const wchar_t *file_name, unsigned int stub_size, bool append_mode, pfile_info mapped_file_info);
PIMAGE_SECTION_HEADER add_section(const char *section_name, unsigned int section_size, void *image_addr);
void copy_stub_instructions(PIMAGE_SECTION_HEADER section, void *image_addr, void *stub_addr);
void change_file_oep(PIMAGE_NT_HEADERS nt_headers, PIMAGE_SECTION_HEADER section);
void write_stub_entry_point(PIMAGE_NT_HEADERS nt_headers, void *stub_addr);