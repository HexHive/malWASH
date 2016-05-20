#pragma once
#include "Injector.h"

void encrypt_file(PIMAGE_NT_HEADERS nt_headers, pfile_info target_file, const char *excluded_section_name);
void encrypt(unsigned int num_rounds, unsigned int blocks[2], unsigned int const key[4]);
void decrypt(unsigned int num_rounds, unsigned int blocks[2], unsigned int const key[4]);
unsigned int swap_endianess(unsigned int value);