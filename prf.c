#include "stdio.h"
#include "hw3_part1.c"

#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
//#include <sys/regs.h>

/*
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%~~FUNCTIONS~~%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
*/

/*
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%~~IMPLEMENTAIONS~~%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
*/

int main(int arc, char** argv) {

    /* Get the arguments */
    //char* func_name     = argv[1];
    //char* exe_file_name = argv[2];

    char* func_name     = "add_but_not_really";
    char* exe_file_name = "main.out";

    int error = 0;

    find_symbol(func_name, exe_file_name, &error);

    //int res = prf(func_name, exe_file_name);
    
    //TODO: SWITCH CASE?
    /*
    if (res == FILE_NOT_EXECUTABLE)
    {
        printf("PRFL %s not an executable! :(\n", exe_file_name);
        return 0;
    }
    else if (res == SYM_NOT_FOUND)
    {
        printf("PRF: %s not found!\n", func_name);
        return 0;
    }
    else if (res == SYM_FOUND_AS_LOCAL)
    {
        printf("PRF: %s is not a global symbol! :(\n", func_name);
        return 0;
    }

    printf("Hello world\n");

    */
    return 0;
}


/*
 * Taking care of the special case of an undefined symbol
 * TODO:
 * > Find the dynsym section
 * > Iterate it and find the entrie which belongs to the symbol (just like we did in hw3)
 * > the index ( in the table ) represents the index symbol which will help us idetify the entrie in rela.plt
 * > Find the rela plt section 
 * > iterate the section and find the entrie which ELF64_R_SYM(Info) == the index from before
 * > now the "offset" in the entrie found is the offset from the beginnig of GOT to the sym entrie
 * > now the data in the GOT entrie has the address of the plt that belongs to the symbol
 * > thats the address that we want to put a break point...
 */ 