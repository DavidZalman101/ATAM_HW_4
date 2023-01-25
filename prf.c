#include "hw3_part1.h"
#include "stdio.h"

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

int prf(char* symbol_name, char* exe_file_name);

/*
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%~~IMPLEMENTAIONS~~%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
*/

int prf(char* symbol_name, char* exe_file_name)
{
    /* Call the function "fild_symbol" from hw3 inorder to find info on the file+symbol */
    int error_val    = 0;
    int symbol_index = 0;
    //unsigned long sym_load_adr = find_symbol(symbol_name, exe_file_name, &error_val);

    /* Check if the given file is executalbe */
    if (error_val == FILE_NOT_EXECUTABLE)
        return FILE_NOT_EXECUTABLE;
    
    /* file is an executalbe */
    /* Check if the symbol was found */
    if (error_val == SYM_NOT_FOUND)
        return SYM_NOT_FOUND;
    
    /* Symbol was found in the file */
    /* Check if the symbol is LOCAL */
    if (error_val == SYM_FOUND_AS_LOCAL)
        return SYM_FOUND_AS_LOCAL;

    /* Symbol is either (GLOBAL) or (LOCAL and GLOBAL) */
    /* Check if Symbol is defined in the file */
    if (error_val == SYM_FOUND_AS_GLOBAL_AND_DEFINED_HERE)
    {
        /* Is defined in the file and we know where it will be loaded */
        //TODO: call a function which will follow the return value
        //      of the sym(function)
    }
    else
    {
        /* Is not defined in the file*/
        ///TODO: figure out how to deal with this case
    }
    return true;
}

int main(int arc, char** argv) {

    /* Get the arguments */
    //char* func_name     = argv[1];
    //char* exe_file_name = argv[2];

    char* func_name     = "";
    char* exe_file_name = "";

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