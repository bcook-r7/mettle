#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <arpa/inet.h>

#include "elf.h"


#define MAP(LONG,INT,SHORT) \
	for(ii = 0; ii < SHORT(ehdr->e_phnum); ii++, phdr++) { \
		if(INT(phdr->p_type) == PT_LOAD) { \
			source = data + LONG(phdr->p_offset); \
			dest = mapping + LONG(phdr->p_vaddr); \
			len = LONG(phdr->p_filesz); \
			printf("memcpy(%p, %p, %08zx)\n", dest, source, len); \
			memcpy(dest, source, len); \
			used = LONG(phdr->p_memsz) + LONG(phdr->p_vaddr); \
		} \
	}

#define NOP(T) T

#define MAP_LE MAP(NOP,NOP,NOP)
#define MAP_BE MAP(ntohl,ntohl,ntohs)
#define MAP_BE64 MAP(bswap64,ntohl,ntohs)

unsigned long bswap64(unsigned long x)
{
	return (x << 56) | (x << 40 & 0xff000000000000UL) | (x << 24 & 0xff0000000000UL) | (x << 8 & 0xff00000000UL) |
		(x >> 8 & 0xff000000UL) | (x >> 24 & 0xff0000UL) | (x >> 40 & 0xff00UL) | (x >> 56);
}

int main(int argc, char **argv)
{
	int fd;
	struct stat statbuf;
	unsigned char *data; // ELF file
	unsigned char *mapping; // target memory location
	size_t len, used = 0;
	int ii;
	unsigned char *source, *dest;

	Elf32_Ehdr *arch;

	if(argc < 3) {
		printf("elf2bin [input file] [output file]\n");
		exit(EXIT_FAILURE);
	}

	fd = open(argv[1], O_RDONLY);
	if(fd == -1) {
		printf("Failed to open %s: %s\n", argv[1], strerror(errno));
		exit(EXIT_FAILURE);
	}

	if(fstat(fd, &statbuf) == -1) {
		printf("Failed to fstat(fd): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	data = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if(data == MAP_FAILED) {
		printf("Unable to read ELF file in: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	close(fd);

	mapping = mmap(NULL, 0x1000000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if(mapping == MAP_FAILED) {
		printf("Failed to mmap(): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	memset(mapping, 0, 0x1000000);

	printf("data @ %p, mapping @ %p\n", data, mapping);

	arch = (Elf32_Ehdr *)data;

	if (arch->e_ident[EI_CLASS] == ELFCLASS32) {
		Elf32_Ehdr *ehdr = (Elf32_Ehdr *)data;
		Elf32_Phdr *phdr = (Elf32_Phdr *)(data + ehdr->e_phoff);

		if (arch->e_ident[EI_DATA] == ELFDATA2LSB) {
			MAP_LE
		} else {
			phdr = (Elf32_Phdr *)(data + ntohl(ehdr->e_phoff));
			MAP_BE
		}
	} else {
		Elf64_Ehdr *ehdr = (Elf64_Ehdr *)data;
		Elf64_Phdr *phdr = (Elf64_Phdr *)(data + ehdr->e_phoff);

		if (arch->e_ident[EI_DATA] == ELFDATA2LSB) {
			MAP_LE
		} else {
			phdr = (Elf64_Phdr *)(data + bswap64(ehdr->e_phoff));
			MAP_BE64
		}
	}

	fd = open(argv[2], O_RDWR|O_TRUNC|O_CREAT, 0644);
	if(fd == -1) {
		printf("Unable to dump memory: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if(write(fd, mapping, used) != used) {
		printf("Unable to complete memory dump\n");
		exit(EXIT_FAILURE);
	}

	close(fd);

	return 0;
}
