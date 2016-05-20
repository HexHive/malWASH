#include "Encrypter.h"
#include <stdio.h>

void encrypt_file(PIMAGE_NT_HEADERS nt_headers, pfile_info target_file, const char *excluded_section_name) {
    PIMAGE_SECTION_HEADER current_section = IMAGE_FIRST_SECTION(nt_headers);
    const char *excluded_sections[] = {".rdata", ".rsrc", excluded_section_name};
    for(int i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
        int excluded = 1;
        for(int j = 0; j < sizeof(excluded_sections)/sizeof(excluded_sections[0]); ++j)
            excluded &= strcmp(excluded_sections[j], (char *)current_section->Name);
        if(excluded != 0) {
            unsigned char *section_start = 
                (unsigned char *)target_file->file_mem_buffer + current_section->PointerToRawData;
            unsigned char *section_end = section_start + current_section->SizeOfRawData;
            const unsigned int num_rounds = 32;
            const unsigned int key[] = {0x12345678, 0xAABBCCDD, 0x10101010, 0xF00DBABE};
            for(unsigned char *k = section_start; k < section_end; k += 8) {
                unsigned int block1 = (*k << 24) | (*(k+1) << 16) | (*(k+2) << 8) | *(k+3);
                unsigned int block2 = (*(k+4) << 24) | (*(k+5) << 16) | (*(k+6) << 8) | *(k+7);
                unsigned int full_block[] = {block1, block2};
                encrypt(num_rounds, full_block, key);
                full_block[0] = swap_endianess(full_block[0]);
                full_block[1] = swap_endianess(full_block[1]);
                memcpy(k, full_block, sizeof(full_block));
            }
        }
        current_section++;
    }
}

//Encryption/decryption routines modified from http://en.wikipedia.org/wiki/XTEA
void encrypt(unsigned int num_rounds, unsigned int blocks[2], unsigned int const key[4]) {
    const unsigned int delta = 0x9E3779B9;
    unsigned int sum = 0;
    for (unsigned int i = 0; i < num_rounds; ++i) {
        blocks[0] += (((blocks[1] << 4) ^ (blocks[1] >> 5)) + blocks[1]) ^ (sum + key[sum & 3]);
        sum += delta;
        blocks[1] += (((blocks[0] << 4) ^ (blocks[0] >> 5)) + blocks[0]) ^ (sum + key[(sum >> 11) & 3]);
    }
}
 
//Unused, kept for testing/verification
void decrypt(unsigned int num_rounds, unsigned int blocks[2], unsigned int const key[4]) {
    const unsigned int delta = 0x9E3779B9;
    unsigned int sum = delta * num_rounds;
    for (unsigned int i = 0; i < num_rounds; ++i) {
        blocks[1] -= (((blocks[0] << 4) ^ (blocks[0] >> 5)) + blocks[0]) ^ (sum + key[(sum >> 11) & 3]);
        sum -= delta;
        blocks[0] -= (((blocks[1] << 4) ^ (blocks[1] >> 5)) + blocks[1]) ^ (sum + key[sum & 3]);
    }
}

inline unsigned int swap_endianess(unsigned int value) {
    return (value >> 24) |  ((value << 8) & 0x00FF0000) |
        ((value >> 8) & 0x0000FF00) | (value << 24);
}