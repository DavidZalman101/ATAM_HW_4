/*
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%~~INCLUDES~~%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
*/

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "elf64.h"

/*
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%~~DEFINES~~%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
*/

#define	ET_NONE	0	//No file type 
#define	ET_REL	1	//Relocatable file 
#define	ET_EXEC	2	//Executable file 
#define	ET_DYN	3	//Shared object file 
#define	ET_CORE	4	//Core file 


/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */
/*_______________________________________________________________________________________________________________*/

	#ifndef STB_LOCAL
	#define STB_LOCAL 0
	#endif

	#ifndef STB_GLOBAL
	#define STB_GLOBAL 1
	#endif

	#ifndef STB_LOCAL_AND_GLOBAL
	#define STB_LOCAL_AND_GLOBAL 2
	#endif

	#ifndef STB_WEAK
	#define STB_WEAK 2
	#endif

	#ifndef SYM_NOT_FOUND 
	#define SYM_NOT_FOUND -1
	#endif

	#ifndef SYM_FOUND_AS_LOCAL
	#define SYM_FOUND_AS_LOCAL -2
	#endif

	#ifndef SYM_FOUND_AS_GLOBAL_AND_DEFINED_HERE
	#define SYM_FOUND_AS_GLOBAL_AND_DEFINED_HERE 1
	#endif

	#ifndef FILE_NOT_EXECUTABLE
	#define FILE_NOT_EXECUTABLE -3
	#endif

	#ifndef SYM_FOUND_GLOBAL_NOT_DEFINED_HERE 
	#define SYM_FOUND_GLOBAL_NOT_DEFINED_HERE -4
	#endif

	#ifndef FAIL
	#define FAIL -3
	#endif
    
/*
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%~~FUNCTIONS~~%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
*/
bool find_header_of_elffile(FILE* fd, Elf64_Ehdr* file_header_ptr);

bool find_shstrtab_header(FILE* fd, Elf64_Shdr* shstrtab_section_header, Elf64_Ehdr* file_header_ptr);

int get_str_length( FILE* fd, long start_adr);

char* get_section_name( FILE* fd, Elf64_Shdr* section_header, Elf64_Shdr* shstrtab_section_headerd );

bool find_sym_str_tabs_section_headers
( FILE* fd, 						 			Elf64_Half Number_of_section_header_enteries, 
  Elf64_Shdr* symtab_section_header, 			Elf64_Shdr* strtab_section_header,
  Elf64_Shdr* shstrtab_section_header,			Elf64_Ehdr* file_header_ptr
);

char* find_string_in_strtab( FILE* fd, Elf64_Shdr* strtab_section_header, Elf64_Sym* symtab_entrie );

int search_symtab( FILE* fd,
				    Elf64_Shdr* symtab_section_header, 	 Elf64_Shdr* strtab_section_header,
					char* symbol_name, bool* defined_here, Elf64_Sym* symtab_entrie_sym_name);


unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val);

bool find_section_headers(FILE* fd, Elf64_Shdr* sections, Elf64_Ehdr header);

bool find_dynstr_section(FILE* fd, Elf64_Ehdr* file_header_ptr, Elf64_Shdr* shstrtab_section_header, Elf64_Shdr* dynsym_section_header);

bool find_dynsym_section(FILE* fd , Elf64_Shdr* section_header);

