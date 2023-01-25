#include "stdio.h"
#include "hw3_part1.c"
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

/*
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%~~FUNCTIONS~~%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
*/

void run_debuger(pid_t child_pid, unsigned long func_load_adr, bool is_dynamic) {
    int func_entry_counter = is_dynamic ? -1 : 0;
    struct user_regs_struct regs;
    int wait_status = 1;
    bool is_recursive = false;

    /* Wait for the child to send ptrace signal */
    waitpid(child_pid, &wait_status, 0);

    /* Save the instructions (8 bytes) */
    /* Note: they are not "legal" instructions, we're taking a junk */
    unsigned long saved_instructions = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) (func_load_adr), NULL);

    /* Write a breakpoint */
    unsigned long clear_and_break = (saved_instructions & 0xFFFFFFFFFFFFFF00) | 0xCC;

    /* Write the 'clear_and_break' data at func_load_adr */
    ptrace(PTRACE_POKETEXT, child_pid, (void *) func_load_adr, (void *) clear_and_break);

    /* Let the son continue running, he'll stop at 'func_load_adr' since we inserted a breakpoint there */
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);

    /* Wait until the son reaches the breakpoint */
    wait(&wait_status);

    while (WIFSTOPPED(wait_status)) {
        /* Get the set of registers */
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

        unsigned long return_address = ptrace(PTRACE_PEEKTEXT, child_pid, regs.rsp, NULL);
        unsigned long return_data = ptrace(PTRACE_PEEKTEXT, child_pid, return_address, NULL);
        unsigned long re_addr_cmd = (return_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
        is_recursive = return_address == func_load_adr;

        ptrace(PTRACE_POKETEXT, child_pid, return_address, (void *) (re_addr_cmd));

        // Restoring original command.
        ptrace(PTRACE_POKETEXT, child_pid, func_load_adr, (void *) (saved_instructions));

        --regs.rip;

        ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

        ptrace(PTRACE_CONT, child_pid, NULL, NULL);

        wait(&wait_status);

        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        ++func_entry_counter;

        if (func_entry_counter > 0 || !is_recursive) {
            printf("PRF:: run #%d returned with %d", func_entry_counter, (int) regs.rax);
        }

        --regs.rip;
        ptrace(PTRACE_POKETEXT, child_pid, return_address, (void *) (return_data));

        ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

        ptrace(PTRACE_POKETEXT, child_pid, (void *) func_load_adr, (void *) clear_and_break);
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);

        wait(&wait_status);
    }


}


pid_t create_son_and_start_trace(const char *exe_file_name, char **argv) {
    // create a son proc to debug
    pid_t pid = fork();

    /* Father should just leave the function */
    /* Son should ask to be traced and go run the exe file */
    if (pid > 0)
        // Fathers code
        return pid;
    if (pid < 0) {
        printf("ERROR: fork");
        exit(1);
    }

    // Sons code
    // Ask to be traced
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
        printf("ERROR: ptrace");
        exit(1);
    }
    /* I choose execl because I want to send him "argv[2:-1]" (a Null terminated string of the arguments)*/
    execl(exe_file_name, *(argv + 2), NULL);
}

int prf(char *symbol_name, char *exe_file_name, char **argv) {
    /* Call the function "fild_symbol" from hw3 inorder to find info on the file+symbol */
    int error_val = 0;
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

    /* Starting debugging */
    pid_t child_pid = create_son_and_start_trace(exe_file_name, argv);

    run_debuger(child_pid, sym_load_adr, error_val == SYM_FOUND_AS_GLOBAL_AND_DEFINED_HERE);
    return true;
}

/*
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%~~IMPLEMENTAIONS~~%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
*/

int main(int arc, char **argv) {

    /* Get the arguments */
    //char* func_name     = argv[1];
    //char* exe_file_name = argv[2];

    char *func_name = "add_but_not_really";
    char *exe_file_name = "main.out";

    int res = prf(func_name, exe_file_name, argv);

    if (res == FILE_NOT_EXECUTABLE) {
        printf("PRFL %s not an executable! :(\n", exe_file_name);
        return 0;
    } else if (res == SYM_NOT_FOUND) {
        printf("PRF: %s not found!\n", func_name);
        return 0;
    } else if (res == SYM_FOUND_AS_LOCAL) {
        printf("PRF: %s is not a global symbol! :(\n", func_name);
        return 0;
    }

    return 0;
}


