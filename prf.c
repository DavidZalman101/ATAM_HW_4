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

void run_debuger(pid_t child_pid, unsigned long func_load_adr)
{

    int func_entrie_counter = 0;
    int wait_status         = 1;
    struct user_regs_struct_regs regs;

    /* Wait for the child to send ptrace signal */
    waitpid(child_pid, &wait_status, 0);

    /* Save the instructions (8 bytes) */
    /* Note: they are not "legal" instructions, we're taking a junk */
    unsigned long saved_instructions = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)func_load_adr, NULL);
    
    /* Write a breakpoint */
    unsigned long clear_and_break    = (saved_instructions & 0xFFFFFFFFFFFFFF00) | 0xCC;

    /* Write the 'clear_and_break' data at func_load_adr */
    ptrace(PTRACE_POKETEXT, child_pid, (void*)func_load_adr, (void*)clear_and_break);

    /* Let the son continue running, he'll stop at 'func_load_adr' since we inserted a breakpoint there */
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);

    /* Wait until the son reaches the breakpoint */
    wait(&wait_status);

    bool inside_function = true;

    while(WIFSTOPPED(wait_status))
    {
        /* Get the set of registers */
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

        /* Since we just entered a function(after a call), we know that at rsp sits the return adress */

        /* get rsp */
        unsigned long rsp = regs.rsp;

        /* Restore the original instruction */
        ptrace(PTRACE_POKETEXT, child_pid,  (void*)func_load_adr, (void*)saved_instructions);

        /* Get the instructions at 'return address' */
        Elf64_Addr return_address = ptrace(PTRACE_PEEKTEXT, child_pid, rsp, NULL);
        unsigned long return_address_instructions = ptrace(PTRACE_PEEKTEXT, child_pid, return_address, NULL);

        /* Set a break point at the at the return address */
        unsigned long clear_and_break_return_address_instructions = (return_address_instructions &0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, child_pid, return_address, (void*)clear_and_break_return_address_instructions);

        /* Set the instruction pointer a step behind (since we had a breakpoint we executed) */
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        regs.rip--;
        ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

        /* Run until reached the break point which sits at the return address */
        ///TODO: Continue from here

    }
}



void create_son_and_start_trace(const char* exe_file_name, char** argv)
{
    // create a son proc to debug
    pid_t pid = fork();

    /* Father should just leave the function */
    /* Son should ask to be traced and go run the exe file */
    if (pid > 0)
        // Fathers code
        return;

    else if (pid == 0)
    {
        // Sons code
        // Ask to be traced
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
        {
            printf("ERROR: ptrace");
            exit(1);
        }
        /* I choose execl because I want to send him "argv[2:-1]" (a Null terminated string of the arguments)*/
        execl(exe_file_name, *(argv+2), NULL);
    }
    else
    {
        printf("ERROR: fork");
        exit(1);
    }
}


int prf(char* symbol_name, char* exe_file_name)
{
    /* Call the function "fild_symbol" from hw3 inorder to find info on the file+symbol */
    int error_val    = 0;
    int symbol_index = 0;
    unsigned long sym_load_adr = find_symbol(symbol_name, exe_file_name, &error_val);

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
        
    }
    else
    {

    }
    return true;
}

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

    int res = prf(func_name, exe_file_name);
    
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

    return 0;
}


