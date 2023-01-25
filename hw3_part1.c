/*
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%~~INCLUDES~~%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
*/
#include <stdio.h>
#include<stdarg.h>
#include<signal.h>
#include<syscall.h>
#include<sys/ptrace.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <stdbool.h>
#include "elf64.h"

/*
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%~~DEFINES~~%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
*/

#define    ET_NONE    0    //No file type
#define    ET_REL    1    //Relocatable file
#define    ET_EXEC    2    //Executable file
#define    ET_DYN    3    //Shared object file
#define    ET_CORE    4    //Core file

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

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
bool find_header_of_elffile(FILE *fd, Elf64_Ehdr *file_header_ptr);
/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
bool find_shstrtab_header(FILE *fd, Elf64_Shdr *shstrtab_section_header, Elf64_Ehdr *file_header_ptr);

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
int get_str_length(FILE *fd, long start_adr);

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
char *get_section_name(FILE *fd, Elf64_Shdr *section_header, Elf64_Shdr *shstrtab_section_headerd);
/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
bool find_sym_str_tabs_section_headers
        (FILE *fd, Elf64_Half Number_of_section_header_enteries,
         Elf64_Shdr *symtab_section_header, Elf64_Shdr *strtab_section_header,
         Elf64_Shdr *shstrtab_section_header, Elf64_Ehdr *file_header_ptr, Elf64_Shdr *dynstr_section_header,
         Elf64_Shdr *rela_plt_section_header, Elf64_Shdr *gotplt_section_header
        );

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
char *find_string_in_strtab(FILE *fd, Elf64_Shdr *strtab_section_header, Elf64_Sym *symtab_entrie);

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
int search_symtab(FILE *fd,
                  Elf64_Shdr *symtab_section_header, Elf64_Shdr *strtab_section_header,
                  char *symbol_name, bool *defined_here, Elf64_Sym *symtab_entrie_sym_name);

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
unsigned long find_symbol(char *symbol_name, char *exe_file_name, int *error_val);
/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
bool find_dynsym_section(FILE *fd, Elf64_Ehdr *file_header_ptr, Elf64_Shdr *shstrtab_section_header,
                         Elf64_Shdr *dynsym_section_header);
/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
bool find_the_symbol_index(FILE *fd, Elf64_Shdr *dynsym_section_header, Elf64_Shdr *strtab_section_header,
                           char *symbol_name, int *symbol_index);

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
unsigned long find_sym_got_address(FILE *fd, Elf64_Ehdr *file_header_ptr, Elf64_Shdr *shstrtab_section_header,
                                   Elf64_Shdr *strtab_section_header, char *symbol_name,
                                   Elf64_Shdr *relplt_section_header, Elf64_Shdr *gotplt_section_header);

/*file the header of the eldfile*/
/*return value: - if found - True, else - false*/
bool find_header_of_elffile(FILE *fd, Elf64_Ehdr *file_header_ptr) {
    if (fread((void *) (file_header_ptr), sizeof(u_int8_t), sizeof(Elf64_Ehdr), fd) != sizeof(Elf64_Ehdr)) {
        fclose(fd);
        return false;
    }
    return true;
}
/*_______________________________________________________________________________________________________________*/
/*finds the shstr section header*/
/*return value: if found - True, else - False */
bool find_shstrtab_header(FILE *fd, Elf64_Shdr *shstrtab_section_header, Elf64_Ehdr *file_header_ptr) {
    Elf64_Half shstrtab_index_in_section_table = file_header_ptr->e_shstrndx;
    /*offset_to_shstrtab_relative_to_start_of_file := offset of section table from the start of the file + index * size of section header entrie*/
    long offset_to_shstrtab_relative_to_start_of_file =
            file_header_ptr->e_shoff + (file_header_ptr->e_shentsize * (shstrtab_index_in_section_table));

    /*change the indicator to point at the section of shstrab*/
    if (fseek(fd, offset_to_shstrtab_relative_to_start_of_file, SEEK_SET) != 0) {
        fclose(fd);
        return false;
    }

    /*Read the section header from the file*/
    if (fread((void *) (shstrtab_section_header), sizeof(u_int8_t), sizeof(Elf64_Shdr), fd) != sizeof(Elf64_Shdr)) {
        fclose(fd);
        return false;
    }
    return true;
}
/*_______________________________________________________________________________________________________________*/
/*get the number of bytes that are non NULL from start_adr (an offset relative to the begining of the file)*/
/*NOTE: doesn't count the last NULL byte*/
int get_str_length(FILE *fd, long start_adr) {
    int counter = 0;

    /*Change the indicator to point at the string*/
    if (fseek(fd, start_adr, SEEK_SET) != 0)
        return -1;

    uint8_t byte = 0;
    bool flag = true;

    while (flag) {
        /*Read a byte*/
        // Read the next section header
        if (fread((void *) (&byte), sizeof(u_int8_t), 1, fd) != 1)
            return -1;

        byte == 0 ? flag = false : counter++;
    }
    return counter;
}

/*_______________________________________________________________________________________________________________*/
char *get_section_name(FILE *fd, Elf64_Shdr *section_header, Elf64_Shdr *shstrtab_section_headerd) {
    /*offset_for_str := offset of shstrtab from the start of the file + offset of the string from the start of the shstrrab*/
    long offset_for_str = shstrtab_section_headerd->sh_offset + section_header->sh_name;

    int len = get_str_length(fd, offset_for_str);
    if (len == 0 || len == -1)
        return NULL;

    /*build and insert the string*/
    char *section_name = malloc(sizeof(char) * (len + 1));

    /*Change the indicator to point at the string*/
    if (fseek(fd, offset_for_str, SEEK_SET) != 0) {
        return NULL;
    }

    // Read the next section header
    if (fread((void *) (section_name), sizeof(char), len + 1, fd) != len + 1)
        return NULL;

    return section_name;
}
/*_______________________________________________________________________________________________________________*/
/*Finds the symtab section header and the strtab section header in the section header table*/
/*return value: if we found both - True, else - False */
bool find_sym_str_tabs_section_headers
        (FILE *fd, Elf64_Half Number_of_section_header_enteries,
         Elf64_Shdr *symtab_section_header, Elf64_Shdr *strtab_section_header,
         Elf64_Shdr *shstrtab_section_header, Elf64_Ehdr *file_header_ptr, Elf64_Shdr *dynstr_section_header,
         Elf64_Shdr *rela_plt_section_header, Elf64_Shdr *gotplt_section_header
        ) {
    if (Number_of_section_header_enteries == 0) {
        fclose(fd);
        return false;
    }

    /*2 flags that will tell us by the end if we found both of the section headers(strtab, symtab)*/
    bool found_the_symtab_section = false;
    bool found_the_strtab_section = false;

    /*2 strings to help us find the section headers*/
    char symtab[] = ".symtab";
    char strtab[] = ".strtab";
    char dyntab[] = ".dynstr";
    char relplt[] = ".rela.plt";
    char gotplt[] = ".got.plt";

    /*create a section header iterator to iterate over the section table*/
    Elf64_Shdr section_header;

    /*start iterating*/
    for (int i = 0; i < Number_of_section_header_enteries; i++) {
        /*offset_on_section_tab := offset from the start of the table + i * size of table entrie*/
        long offset_on_section_tab = file_header_ptr->e_shoff + (i * file_header_ptr->e_shentsize);

        /*Change the indicator to point at the next entrie\string of the STR TABLE*/
        if (fseek(fd, offset_on_section_tab, SEEK_SET) != 0) {
            fclose(fd);
            return false;
        }

        /*Read the next section header*/
        if (fread((void *) (&section_header), sizeof(char), sizeof(Elf64_Shdr), fd) != sizeof(Elf64_Shdr)) {
            fclose(fd);
            return false;
        }

        /*Get the string name of the section header*/
        char *section_name_str = get_section_name(fd, &section_header, shstrtab_section_header);

        if (section_name_str == NULL)
            continue;

            /*check if we got the symbol headeri*/
        else if (strcmp(section_name_str, symtab) == 0) {
            // found the symtab section
            *symtab_section_header = section_header;
            found_the_symtab_section = true;
        }

            /*check if we got the strings section*/
        else if (strcmp(section_name_str, strtab) == 0) {
            // found the strtab section
            *strtab_section_header = section_header;
            found_the_strtab_section = true;
        } else if (strcmp(section_name_str, dyntab) == 0) {
            // found the dyntab section
            *dynstr_section_header = section_header;
        } else if (strcmp(section_name_str, relplt) == 0) {
            // found the dyntab section
            *rela_plt_section_header = section_header;
        } else if (strcmp(section_name_str, gotplt) == 0) {
            // found the dyntab section
            *gotplt_section_header = section_header;
        }

        free(section_name_str);
    }
    return (found_the_strtab_section && found_the_symtab_section);
}

/*_______________________________________________________________________________________________________________*/
char *find_string_in_strtab(FILE *fd, Elf64_Shdr *strtab_section_header, Elf64_Sym *symtab_entrie) {
    long offset_for_str = strtab_section_header->sh_offset + symtab_entrie->st_name;
    int len = get_str_length(fd, offset_for_str);
    char *string_to_read = malloc(sizeof(char) * (len + 1));

    /*Change the indicator to point at the next entrie\string of the STR TABLE*/
    if (fseek(fd, offset_for_str, SEEK_SET) != 0) {
        fclose(fd);
        return 0;
    }

    // read the next entrie in symtab and insert it into string_to_read
    if (fread((void *) (string_to_read), sizeof(char), len + 1, fd) != len + 1) {
        fclose(fd);
        return NULL;
    }
    return string_to_read;
}




//TODO:this is the same as the "find_string_in_strtab"... maybe unite them to one function?

char *find_string_in_dyntab(FILE *fd, Elf64_Shdr *dyntab_section_header, Elf64_Sym *dynsym_entrie) {
    long offset_for_str = dyntab_section_header->sh_offset + dynsym_entrie->st_name;
    int len = get_str_length(fd, offset_for_str);
    char *string_to_read = malloc(sizeof(char) * (len + 1));

    if (fseek(fd, offset_for_str, SEEK_SET) != 0) {
        fclose(fd);
        return NULL;
    }

    if (fread((void *) (string_to_read), sizeof(char), len + 1, fd) != len + 1) {
        fclose(fd);
        return NULL;
    }

    return string_to_read;


}


/*_______________________________________________________________________________________________________________*/
int search_symtab(FILE *fd,
                  Elf64_Shdr *symtab_section_header, Elf64_Shdr *strtab_section_header,
                  char *symbol_name, bool *defined_here, Elf64_Sym *symtab_entrie_sym_name) {
    int number_of_entries_in_symtab = symtab_section_header->sh_size / symtab_section_header->sh_entsize;
    Elf64_Sym symtab_entrie;

    bool found_as_global = false;
    bool found_as_local = false;
    // iterate over the n entries
    for (int i = 0; i < number_of_entries_in_symtab - 1; i++) {
        /*Change the indicator to point at the next entrie of the SYM TABLE*/
        long offset_next_entrie_of_the_sym_table =
                symtab_section_header->sh_offset + (i + 1) * symtab_section_header->sh_entsize;
        if (fseek(fd, offset_next_entrie_of_the_sym_table, SEEK_SET) != 0) {
            fclose(fd);
            return FAIL;
        }
        // read the next entrie in symtab
        if (fread((void *) (&symtab_entrie), sizeof(char), sizeof(Elf64_Sym), fd) != sizeof(Elf64_Sym)) {
            fclose(fd);
            return FAIL;
        }

        // NOTE: symtab_entrie.st_name := the offset of the string in the strtab relative to the start of strtab
        char *string_to_read = find_string_in_strtab(fd, strtab_section_header, &symtab_entrie);
        if (string_to_read == NULL)
            continue;

        if (strcmp(string_to_read, symbol_name) == 0) {
            /* check if local or global */
            if (ELF64_ST_BIND(symtab_entrie.st_info) == STB_GLOBAL ||
                ELF64_ST_BIND(symtab_entrie.st_info) == STB_WEAK) {
                *symtab_entrie_sym_name = symtab_entrie;
                found_as_global = true;
            } else if (ELF64_ST_BIND(symtab_entrie.st_info) == STB_LOCAL) {
                *symtab_entrie_sym_name = symtab_entrie;
                found_as_local = true;
            }

            /* check if defined here */
            if (symtab_entrie.st_shndx != SHN_UNDEF)
                *defined_here = true;
        }
        free(string_to_read);
    }

    if (found_as_global == true && found_as_local == true) {
        return STB_GLOBAL;
    } else if (found_as_global == true && found_as_local == false) {
        return STB_GLOBAL;
    } else if (found_as_global == false && found_as_local == true) {
        return STB_LOCAL;
    }
    return SYM_NOT_FOUND;
}

/*_______________________________________________________________________________________________________________*/
unsigned long find_symbol(char *symbol_name, char *exe_file_name, int *error_val) {


    /*Open the file*/
    FILE *fd = fopen(exe_file_name, "r");
    if (fd == NULL) {
        // failed to open the elf_file
        *error_val = FAIL;
        return 0;
    }

    /*Get the elffile header*/
    Elf64_Ehdr file_header_ptr;
    if (find_header_of_elffile(fd, &file_header_ptr) == false) {
        *error_val = FAIL;
        return 0;
    }

    /*Check if this is an exeutable file*/
    if (file_header_ptr.e_type != ET_EXEC) {
        *error_val = FILE_NOT_EXECUTABLE;
        fclose(fd);
        return 0;
    }

    /*Find the section header for the shstr*/
    Elf64_Shdr shstrtab_section_header;
    if (find_shstrtab_header(fd, &shstrtab_section_header, &file_header_ptr) == false) {
        *error_val = FAIL;
        return 0;
    }

    /*Find the symtab and strtab section headers*/
    Elf64_Shdr symtab_section_header;
    Elf64_Shdr strtab_section_header;
    Elf64_Shdr dynstr_section_header;
    Elf64_Shdr relplt_section_header;
    Elf64_Shdr gotplt_section_header;

    if (find_sym_str_tabs_section_headers
                (fd, file_header_ptr.e_shnum,
                 &symtab_section_header, &strtab_section_header,
                 &shstrtab_section_header, &file_header_ptr, &dynstr_section_header,
                 &relplt_section_header, &gotplt_section_header
                ) == false) {
        *error_val = FAIL;
        return 0;
    }

    /*iterate over the symtab entries and look for the string*/
    bool defined_here = false;
    Elf64_Sym symtab_entrie_sym_name;

    int result = search_symtab(fd, &symtab_section_header, &strtab_section_header, symbol_name, &defined_here,
                               &symtab_entrie_sym_name);


    unsigned long res_ = 0;

    if (result == FAIL) {
        *error_val = FAIL;
        res_ = 0;
    } else if (result == STB_GLOBAL) {
        if (symtab_entrie_sym_name.st_shndx != SHN_UNDEF) {
            *error_val = SYM_FOUND_AS_GLOBAL_AND_DEFINED_HERE;
            res_ = symtab_entrie_sym_name.st_value;
        } else {
            *error_val = SYM_FOUND_GLOBAL_NOT_DEFINED_HERE;
            ///TODO: find the dnysym section
            res_ = find_sym_got_address(fd, &file_header_ptr, &shstrtab_section_header, &dynstr_section_header,
                                        symbol_name, &relplt_section_header, &gotplt_section_header);
        }
    } else if (result == STB_LOCAL) {
        *error_val = SYM_FOUND_AS_LOCAL;
    } else if (result == STB_LOCAL_AND_GLOBAL) {
        *error_val = SYM_FOUND_GLOBAL_NOT_DEFINED_HERE;
    } else if (result == SYM_NOT_FOUND) {
        *error_val = SYM_NOT_FOUND;
    }
    fclose(fd);
    return res_;
}
/*_______________________________________________________________________________________________________________*/
bool find_dynsym_section(FILE *fd, Elf64_Ehdr *file_header_ptr, Elf64_Shdr *shstrtab_section_header,
                         Elf64_Shdr *dynsym_section_header) {

    Elf64_Half number_of_header_entires = file_header_ptr->e_shnum;

    if (number_of_header_entires == 0) {
        fclose(fd);
        return 0;
    }

    char dynsym[] = ".dynsym";

    /*create a section header iterator to iterate over the section table*/
    Elf64_Shdr section_header;

    /* Start iterating */
    for (int i = 0; i < number_of_header_entires; i++) {
        /*offset_on_section_tab := offset from the start of the table + i * size of table entrie*/
        long offset_on_section_tab = file_header_ptr->e_shoff + (i * file_header_ptr->e_shentsize);

        if (fseek(fd, offset_on_section_tab, SEEK_SET) != 0) {
            fclose(fd);
            return 0;
        }

        if (fread((void *) (&section_header), sizeof(char), sizeof(Elf64_Shdr), fd) != sizeof(Elf64_Shdr)) {
            fclose(fd);
            return 0;
        }

        char *section_name_str = get_section_name(fd, &section_header, shstrtab_section_header);

        if (section_name_str == NULL)
            continue;

        else if (strcmp(section_name_str, dynsym) == 0) {
            *dynsym_section_header = section_header;
            free(section_name_str);
            return true;
        }
        free(section_name_str);
    }
    return false;

}
/*_______________________________________________________________________________________________________________*/
bool find_the_symbol_index(FILE *fd, Elf64_Shdr *dynsym_section_header, Elf64_Shdr *strtab_section_header,
                           char *symbol_name, int *symbol_index) {

    Elf64_Sym entire;

    Elf64_Xword entrie_size = dynsym_section_header->sh_entsize;
    Elf64_Off offset_into_file = dynsym_section_header->sh_offset;

    Elf64_Half number_of_entries = dynsym_section_header->sh_size / entrie_size;

    for (int i = 0; i < number_of_entries; i++) {

        /* offset_on_section_tab := offset from the begining of the file + i * size of table entrie */
        /* Change the indicator to point at the next entrie of the DYNSYM TABLE */
        long offset_on_section_tab = dynsym_section_header->sh_offset + (i * dynsym_section_header->sh_entsize);

        if (fseek(fd, offset_on_section_tab, SEEK_SET) != 0) {
            fclose(fd);
            return false;
        }

        /* read the next entrie */
        if (fread((void *) (&entire), sizeof(char), sizeof(Elf64_Sym), fd) != sizeof(Elf64_Sym)) {
            fclose(fd);
            return false;
        }

        //TODO: needs a change: use dymtab instead of a strtab....
        char *string_to_read = find_string_in_dyntab(fd, strtab_section_header, &entire);
        if (string_to_read == NULL)
            continue;

        if (strcmp(string_to_read, symbol_name) == 0) {
            *symbol_index = i;
            free(string_to_read);
            return true;
        }
        free(string_to_read);
    }
    return false;
}

/*_______________________________________________________________________________________________________________*/
unsigned long find_sym_got_address(FILE *fd, Elf64_Ehdr *file_header_ptr, Elf64_Shdr *shstrtab_section_header,
                                   Elf64_Shdr *dyntab_section_header, char *symbol_name,
                                   Elf64_Shdr *relplt_section_header, Elf64_Shdr *gotplt_section_header) {

    Elf64_Shdr dynsym_section_header;

    /* Get the dynsym section */
    if (find_dynsym_section(fd, file_header_ptr, shstrtab_section_header, &dynsym_section_header) == false) {
        fclose(fd);
        return 0;
    }

    int symbol_index = 0;
    if (find_the_symbol_index(fd, &dynsym_section_header, dyntab_section_header, symbol_name, &symbol_index) == false) {
        fclose(fd);
        return 0;
    }

    Elf64_Half number_of_entires = relplt_section_header->sh_size / relplt_section_header->sh_entsize;
    Elf64_Rela rel_entrie;

    for (int i = 0; i < number_of_entires; i++) {
        long offset_on_got_tab = relplt_section_header->sh_offset + (i * relplt_section_header->sh_entsize);

        if (fseek(fd, offset_on_got_tab, SEEK_SET) != 0) {
            fclose(fd);
            return 0;
        }

        /* read the entrie */
        if (fread((void *) (&rel_entrie), sizeof(char), sizeof(Elf64_Rela), fd) != sizeof(Elf64_Rela)) {
            fclose(fd);
            return 0;
        }

        if (ELF64_R_SYM(rel_entrie.r_info) == symbol_index) {
            return gotplt_section_header->sh_addr + rel_entrie.r_offset;
        }
    }
    return 0;
}
