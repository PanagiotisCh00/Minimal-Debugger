/* C standard library */
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* POSIX */
#include <unistd.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* Linux */
#include <syscall.h>
#include <sys/ptrace.h>
#include <libelf.h>
#include <gelf.h>
#include <capstone/capstone.h>

// gcc -lcapstone -lelf hw2.c
//  ./a.out ~/hws/hw2/hello

#define TOOL "min_gdb"

#define die(...)                                \
    do                                          \
    {                                           \
        fprintf(stderr, TOOL ": " __VA_ARGS__); \
        fputc('\n', stderr);                    \
        exit(EXIT_FAILURE);                     \
    } while (0)
long unsigned g_text_start = 0;
long unsigned g_text_end = 0;

/**
 * @brief this function loads the elf with libelf and reads the symbol table and add it to the arrays. I add only the functions of the symbol table
 *
 * @param filename name of the binary file
 * @param symTabNames table with the name of the symbols
 * @param symTabAddress table with the address of the symbols
 * @return int
 */
int makeSymbolTable(char *filename, char **symTabNames, long unsigned int *symTabAddress)
// int makeSymbolTable(char *filename, long unsigned int *symTabAddress)
{
    Elf *elf;
    /* Initilization.  */
    if (elf_version(EV_CURRENT) == EV_NONE)
        die("(version) %s", elf_errmsg(-1));
    int fd = open(filename, O_RDONLY);

    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf)
        die("(begin) %s", elf_errmsg(-1));

    /* Loop over sections.  */
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0)
        die("(getshdrstrndx) %s", elf_errmsg(-1));
    while ((scn = elf_nextscn(elf, scn)) != NULL)
    {
        if (gelf_getshdr(scn, &shdr) != &shdr)
            die("(getshdr) %s", elf_errmsg(-1));
        //  the symbol table
        if (!strcmp(elf_strptr(elf, shstrndx, shdr.sh_name), ".symtab"))
        {
            Elf_Data *data;
            GElf_Shdr shdr2;
            int count = 0;
            /* Get the descriptor.  */
            if (gelf_getshdr(scn, &shdr2) != &shdr2)
                die("(getshdr) %s", elf_errmsg(-1));

            data = elf_getdata(scn, NULL);
            count = shdr2.sh_size / shdr2.sh_entsize;

            // symTabAddress = (long unsigned int *)malloc(sizeof(long unsigned int) * count);
            fprintf(stderr, "------------------------------------------------------------------------------------------------------------------\n");
            fprintf(stderr, "Printing symbol table.\n");
            // symTabNames = (char **)malloc(sizeof(char *) * count);
            int j = 0;
            for (int i = 0; i < count; ++i)
            {
                GElf_Sym sym;
                gelf_getsym(data, i, &sym);
                if (ELF64_ST_TYPE(sym.st_info) == STT_FUNC)
                {
                    symTabAddress[j] = sym.st_value;
                    // symTabNames[i] = (char *)malloc(sizeof(char) * 100);
                    symTabNames[j] = malloc(sizeof(char) * strlen(elf_strptr(elf, shdr2.sh_link, sym.st_name) + 1));
                    symTabNames[j] = elf_strptr(elf, shdr2.sh_link, sym.st_name);
                    fprintf(stderr, "address 0x %lx, name %s\n", symTabAddress[j], symTabNames[j]);
                    j++;
                }
            }
            fprintf(stderr, "------------------------------------------------------------------------------------------------------------------\n");
            return j;
        }
    }
    return -1;
}

/**
 * @brief this function prints the current instruction
 *
 * @param pid pid of the process
 */
void process_inspect(int pid)
{
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        die("%s", strerror(errno));
    long current_ins = ptrace(PTRACE_PEEKDATA, pid, regs.rip, 0);
    if (current_ins == -1)
        die("(peekdata) %s", strerror(errno));
    fprintf(stderr, "=> 0x%llx: 0x%lx\n", regs.rip, current_ins);
}

/**
 * @brief Set the breakpoint object
 *
 * @param pid pid of the proccess
 * @param addr it gets the address it will add the breakpoint
 * @param printFlag parameters that enables the function to print that it has set breakPoint.
 * @return long the previous instruction
 */
long set_breakpoint(int pid, long addr, int printFlag)
{
    /* Backup current code.  */
    long previous_code = 0;
    previous_code = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, 0);
    if (previous_code == -1)
        die("(peekdata) %s", strerror(errno));
    if (printFlag == 1)
    {
        fprintf(stderr, "Set breakpoint: %p: 0x%lx\n", (void *)addr, previous_code);
    }
    // fprintf(stderr, "Set breakpoint: %p: 0x%lx\n", (void *)addr, previous_code);
    /* Insert the breakpoint. */
    long trap = (previous_code & 0xFFFFFFFFFFFFFF00) | 0xCC;
    // fprintf(stderr, "trap %lx\n\n", trap);

    if (ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)trap) == -1)
        die("(pokedata) %s", strerror(errno));

    return previous_code;
}
/**
 * @brief makes all the arrays bigger,it goes 40,80 etc.... It uses realloc
 *
 * @param oldInstructions array of old instructions
 * @param breakPointsNames array of names of breakpoints
 * @param breakPointsAddress array of addresses of breakpoints
 * @param count the current size
 */
void makeArraysBigger(long *oldInstructions, char **breakPointsNames, long unsigned int *breakPointsAddress, int count)
{
    oldInstructions = (long *)realloc(oldInstructions, +(40 * sizeof(long)));
    breakPointsNames = (char **)realloc(breakPointsNames, +(40 * sizeof(char) * 100));
    breakPointsAddress = (long unsigned *)realloc(breakPointsAddress, count + (40 * sizeof(long unsigned)));
}

/**
 * @brief checks if a beakpoint with the given name exists
 *
 * @param breakPointsNames array names with all the breakpoints
 * @param breakPoint the breakpoint that is going to be checked
 * @param numOfbreakPoints number of breakpoints
 * @return int returns 0 if it does not exist, returns 1 if it exists
 */
int existsBreakByName(char **breakPointsNames, char *breakPoint, int numOfbreakPoints)
{
    int i;
    for (i = 0; i < numOfbreakPoints; i++)
    {
        if (strcmp(breakPoint, breakPointsNames[i]) == 0)
        {
            return 1;
        }
    }
    return 0;
}
// checks if a beakpoint with that name exists, 0--not exists, 1--exists.
/**
 * @brief checks if a beakpoint with the given address exists
 *
 * @param breakPointsAddressarray with address of all the breakpoints
 * @param breakPoint the breakpoint that is going to be checked
 * @param numOfbreakPoints number of breakpoints
 * @return int returns 0 if it does not exist, returns 1 if it exists
 */
int existsBreakByAddress(long unsigned int *breakPointsAddress, long breakPoint, int numOfbreakPoints)
{
    int i;
    for (i = 0; i < numOfbreakPoints; i++)
    {
        if (breakPointsAddress[i] == breakPoint)
        {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief uses the given name to add a breakpoint to the address of that address
 *
 * @param pid pid of the process
 * @param symTabSize size of the symbol table
 * @param breakpointName the name of the breakpoint
 * @param symTabNames symbols names
 * @param symTabAddress symbols addresses
 * @param oldInstructions array with the old instructions
 * @param breakPointsNames names of the breakpoints
 * @param breakPointsAddress addresses of the breakpoints
 * @param numOfbreakPoints number of the breakpoints
 */
void addOneBreakPointByName(int pid, int symTabSize, char *breakpointName, char **symTabNames, long unsigned int *symTabAddress, long *oldInstructions,
                            char **breakPointsNames, long unsigned int *breakPointsAddress, int *numOfbreakPoints)
{
    int i;
    for (i = 0; i < symTabSize; i++)
    {

        // i found the symbol i want to add the breakpoint
        if (strcmp(symTabNames[i], breakpointName) == 0)
        {
            // fprintf(stderr, "beakpoint name: %s\n", symTabNames[i]);
            breakPointsNames[*numOfbreakPoints] = (char *)malloc(sizeof(char) * strlen(symTabNames[i]));
            strcpy(breakPointsNames[*numOfbreakPoints], symTabNames[i]);
            breakPointsAddress[*numOfbreakPoints] = symTabAddress[i];

            oldInstructions[*numOfbreakPoints] = set_breakpoint(pid, symTabAddress[i], 1);
            (*numOfbreakPoints) = (*numOfbreakPoints) + 1;

            return;
        }
    }
    fprintf(stderr, "\nThis function-symbol name does not exist\n\n");
}
/**
 * @brief uses the given address to add a breakpoint to that address
 *
 * @param pid pid of the process
 * @param symTabSize size of the symbol table
 * @param breakpointAddr address of the breakpoint
 * @param symTabNames symbols names
 * @param symTabAddress symbols addresses
 * @param oldInstructions array with the old instructions
 * @param breakPointsNames names of the breakpoints
 * @param breakPointsAddress addresses of the breakpoints
 * @param numOfbreakPoints number of the breakpoints
 */
void addOneBreakPointByAddress(int pid, int symTabSize, long unsigned int breakpointAddr, char **symTabNames, long unsigned int *symTabAddress, long *oldInstructions,
                               char **breakPointsNames, long unsigned int *breakPointsAddress, int *numOfbreakPoints)
{
    int i;
    // there is chance that the breakpoint is in the symbol table
    for (i = 0; i < symTabSize; i++)
    {
        // fprintf(stderr, "address ine %lx\n", symTabAddress[i]);
        // i found the symbol i want to add the breakpoint
        if (symTabAddress[i] == breakpointAddr)
        {

            // fprintf(stderr, "emphke sto if\n");
            strcpy(breakPointsNames[*numOfbreakPoints], symTabNames[i]);
            breakPointsAddress[*numOfbreakPoints] = symTabAddress[i];
            oldInstructions[*numOfbreakPoints] = set_breakpoint(pid, symTabAddress[i], 1);
            (*numOfbreakPoints) = (*numOfbreakPoints) + 1;
            return;
        }
    }
    // there is chance that its not in the symbol table
    if (breakpointAddr > g_text_start && breakpointAddr < g_text_end) // its in the text section
    {
        strcpy(breakPointsNames[*numOfbreakPoints], ("unknown"));
        breakPointsAddress[*numOfbreakPoints] = breakpointAddr;
        oldInstructions[*numOfbreakPoints] = set_breakpoint(pid, breakpointAddr, 1);
        (*numOfbreakPoints) = (*numOfbreakPoints) + 1;
        // fprintf(stderr, "nato: 0x%p: 0x%lx\n", (void *)breakPointsAddress[*numOfbreakPoints], oldInstructions[*numOfbreakPoints]);
    }
    else
    {
        fprintf(stderr, "This address is not in the text section");
        return;
    }
}

/**
 * @brief it deletes the breakpoint at a given position( ofcourse it adds the previous instruction in that address).
 *
 * @param pid pid of the process
 * @param symTabSize size of the symbol table
 * @param symTabNames symbols names
 * @param symTabAddress symbols addresses
 * @param oldInstructions array with the old instructions
 * @param breakPointsNames names of the breakpoints
 * @param breakPointsAddress addresses of the breakpoints
 * @param numOfbreakPoints number of the breakpoints
 * @param position the position that the breakpoint will be deleted
 */
void delete (int pid, int symTabSize, char **symTabNames, long unsigned int *symTabAddress, long *oldInstructions,
             char **breakPointsNames, long unsigned int *breakPointsAddress, int *numOfbreakPoints, int position)
{
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
    {
        if (errno == ESRCH)
        {
            /* System call was exit; so we need to end.  */
            fprintf(stderr, "finished\n");
            exit(regs.rdi);
        }
        die("%s", strerror(errno));
    }
    int i;
    if (ptrace(PTRACE_POKEDATA, pid, (void *)breakPointsAddress[position], (void *)oldInstructions[position]) == -1)
        die("(pokedata) %s", strerror(errno));
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1)
        die("(setregs) %s", strerror(errno));

    for (i = position; i < (*numOfbreakPoints - 1); i++)
    {
        strcpy(breakPointsNames[i], breakPointsNames[i + 1]);
        breakPointsAddress[i] = breakPointsAddress[i + 1];
        oldInstructions[i] = oldInstructions[i + 1];
    }
    (*numOfbreakPoints) = (*numOfbreakPoints) - 1;
}
/**
 * @brief goes a step ahead
 *
 * @param pid pid of the process
 */
void process_step(int pid)
{
    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)
        die("(singlestep) %s", strerror(errno));

    waitpid(pid, 0, 0);
}

/**
 * @brief serves the breakpoint. checks which breakpoint it is, does poke data to add previous instruction to that address so it will continue okay
 *
 * @param pid pid of the current proccess
 * @param oldInstructions array with the old instructions
 * @param breakPointsNames array with the names of the breakpoints
 * @param breakPointsAddress array with the address of the breakpoints
 * @param numOfbreakPoints number of the breakpoints
 * @return int returns the position in the arrays that the breakpoint that occured was
 */
int serve_breakpoint(int pid, long *oldInstructions,
                     char **breakPointsNames, long unsigned int *breakPointsAddress, int *numOfbreakPoints)
{
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
    {
        if (errno == ESRCH)
        {
            /* System call was exit; so we need to end.  */
            fprintf(stderr, "The program is Done, has finished.\n");
            exit(regs.rdi);
        }
        die("%s", strerror(errno));
    }
    // o regs.rip exei th dievthinsi pou ime twra
    int i;
    for (i = 0; i < *numOfbreakPoints; i++)
    {
        if (regs.rip - 1 == breakPointsAddress[i])
        {
            if (ptrace(PTRACE_POKEDATA, pid, (void *)breakPointsAddress[i], (void *)oldInstructions[i]) == -1)
                die("(pokedata) %s", strerror(errno));
            regs.rip = breakPointsAddress[i];
            if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1)
                die("(setregs) %s", strerror(errno));
            process_inspect(pid);
            return i;
        }
    }
    fprintf(stderr, "did not found the breakpoint.\n");
    return -1;
}

/**
 * @brief it does linear disassemble.Disassembles the .text and prints only from the addr it is now and the next 10
 * instructions or untill a retq.
 *
 * @param handle the handler that is needed by cs_disasm
 * @param buffer the buffer with the whole .text section
 * @param addr the address i want to start the disassemble
 * @param textStart the address that the .text section start
 * @param size the size i want to disasemble
 */
void disas(csh handle, long unsigned int addr, Elf_Data *textData)
{
    cs_insn *cs_ins;
    uint64_t offset;
    const uint8_t *pc;
    offset = addr - g_text_start;
    pc = (const unsigned char *)textData->d_buf;
    pc += offset;
    size_t n = g_text_end - g_text_start;
    cs_ins = cs_malloc(handle);
    int i;
    for (i = 0; i < 10; i++)
    {
        cs_disasm_iter(handle, &pc, &n, &addr, cs_ins);
        if (!strcmp(cs_ins->mnemonic, "retq"))
        {
            fprintf(stderr, "0x%" PRIx64 ":\t%s\t\t%s\n", cs_ins->address, cs_ins->mnemonic, cs_ins->op_str);
            return;
        }
        else
        {
            fprintf(stderr, "0x%" PRIx64 ":\t%s\t\t%s\n", cs_ins->address, cs_ins->mnemonic, cs_ins->op_str);
        }
    }
}

/**
 * @brief the main function , provides the menus and all the functionalities. For every functionality calls the right functions
 *
 * @param symTabNames names of the symboles
 * @param symTabAddress addresses of the symbols
 * @param argv to know the process it has to trace
 * @param symTabSize size of the symbol table
 * @param filename the name of the binary it will examine
 */
void breakPointMainFun(char **symTabNames, long unsigned int *symTabAddress, char **argv, int symTabSize, char *filename)
{
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return;

    /* AT&T */
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
    Elf *elf;
    Elf_Data *textData = NULL;

    /* Initilization.  */
    if (elf_version(EV_CURRENT) == EV_NONE)
        die("(version) %s", elf_errmsg(-1));

    int fd = open(filename, O_RDONLY);

    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf)
        die("(begin) %s", elf_errmsg(-1));

    /* Loop over sections.  */
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0)
        die("(getshdrstrndx) %s", elf_errmsg(-1));
    while ((scn = elf_nextscn(elf, scn)) != NULL)
    {
        if (gelf_getshdr(scn, &shdr) != &shdr)
            die("(getshdr) %s", elf_errmsg(-1));

        /* Locate .text  */
        if (!strcmp(elf_strptr(elf, shstrndx, shdr.sh_name), ".text"))
        {
            textData = elf_getdata(scn, textData);
            if (!textData)
                die("(getdata) %s", elf_errmsg(-1));

            g_text_start = shdr.sh_addr;
            g_text_end = g_text_start + shdr.sh_size;
        }
    }

    /* fork() for executing the program that is analyzed.  */
    pid_t pid = fork();
    switch (pid)
    {
    case -1: /* error */
        die("%s", strerror(errno));
    case 0: /* Code that is run by the child. */
        /* Start tracing.  */
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        /* execvp() is a system call, the child will block and
           the parent must do waitpid().
           The waitpid() of the parent is in the label
           waitpid_for_execvp.
         */
        execvp(argv[1], argv + 1);
        die("%s", strerror(errno));
    }
    /* Code that is run by the parent.  */
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);
    waitpid(pid, 0, 0);

    long *oldInstructions = (long *)malloc(sizeof(long) * 40);
    char **breakPointsNames;
    breakPointsNames = malloc(sizeof(char *) * 40);
    int i = 0;
    for (i = 0; i < 40; i++)
    {
        breakPointsNames[i] = (char *)malloc(sizeof(char) * 100);
    }
    long unsigned int *breakPointsAddress = (long unsigned int *)malloc(sizeof(long unsigned int) * 40);
    int numOfbreakPoints = 0;
    while (1)
    {
        fprintf(stderr, "\nGive me the function you want:\n b-breakpoint\n l to list\n d to delete\n r to run\n c to continue \n");
        char mode;
        // char *dataRead = getlineChars();
        char dataRead[1024];
        char akiro;
        scanf("%[^\n]%c", dataRead, &akiro);

        // fprintf(stderr, "str: %s--\n", dataRead);
        mode = dataRead[0];
        if (mode == 'b')
        {
            // fprintf(stderr, "given data: %s\n", dataRead);
            if (dataRead[2] == '*')
            { // address starts from position=3
                // fprintf(stderr, "edwse address\n");
                char tempAdd[strlen(dataRead) - 3];
                char *ptr;
                strcpy(tempAdd, dataRead + 3);

                long unsigned int newbreakpointAddr;
                newbreakpointAddr = strtoul(tempAdd, &ptr, 16);
                if (existsBreakByAddress(breakPointsAddress, newbreakpointAddr, numOfbreakPoints) == 0)
                {
                    addOneBreakPointByAddress(pid, symTabSize, newbreakpointAddr, symTabNames, symTabAddress, oldInstructions, breakPointsNames, breakPointsAddress,
                                              &numOfbreakPoints);
                }
                else
                {
                    fprintf(stderr, "This breakpoint is already inserted\n");
                }
            }
            else
            {
                // fprintf(stderr, "size %d-%s-\n", strlen(dataRead), dataRead);
                int strSize = strlen(dataRead);
                char tempDat[strSize - 2];
                strcpy(tempDat, dataRead + 2);
                // fprintf(stderr, "sizes: %d-%s-\n", strlen(tempDat), tempDat);
                if (existsBreakByName(breakPointsNames, tempDat, numOfbreakPoints) == 0)
                {
                    if (numOfbreakPoints % 40 == 0)
                    { // then i have to make the arrays bigger
                        makeArraysBigger(oldInstructions, breakPointsNames, breakPointsAddress, numOfbreakPoints);
                    }
                    addOneBreakPointByName(pid, symTabSize, tempDat, symTabNames, symTabAddress, oldInstructions, breakPointsNames, breakPointsAddress, &numOfbreakPoints);
                }
                else
                {
                    fprintf(stderr, "This breakpoint is already inserted\n");
                }
            }
        }
        else if (mode == 'l')
        {
            fprintf(stderr, "printing the breakpoints, %d\n\n", numOfbreakPoints);
            int i = 0;
            for (i = 0; i < numOfbreakPoints; i++)
            {
                fprintf(stderr, "%d : %s,  %lx\n", i + 1, breakPointsNames[i], breakPointsAddress[i]);
            }
            fprintf(stderr, "\n");
        }
        else if (mode == 'd')
        {
            char tempDat[strlen(dataRead) - 2];
            char *ptr;
            strcpy(tempDat, dataRead + 2);
            int position = strtoul(tempDat, &ptr, 10);
            position = position - 1;
            if (position > numOfbreakPoints)
            {
                fprintf(stderr, "This breakPoint does not exist\n");
            }
            else
            {
                delete (pid, symTabSize, symTabNames, symTabAddress, oldInstructions, breakPointsNames, breakPointsAddress, &numOfbreakPoints, position);
                fprintf(stderr, "Breakpoint Deleted\n");
            }
        }

        else if (mode == 'r')
        {
            /* Resume process.  */
            if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)
                die("(cont) %s", strerror(errno));
            waitpid(pid, 0, 0);
            /* We are in the breakpoint.  */
            int pos = serve_breakpoint(pid, oldInstructions,
                                       breakPointsNames, breakPointsAddress, &numOfbreakPoints);
            disas(handle, breakPointsAddress[pos], textData);
            process_step(pid); // pairnei me ena mprosta
            set_breakpoint(pid, breakPointsAddress[pos], 0);
        }
        else if (mode == 'c')
        {
            /* Resume process.  */
            if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)
                die("(cont) %s", strerror(errno));
            waitpid(pid, 0, 0);
            /* We are in the breakpoint.  */
            int pos = serve_breakpoint(pid, oldInstructions, breakPointsNames, breakPointsAddress, &numOfbreakPoints);
            process_step(pid); // pairnei me ena mprosta
            set_breakpoint(pid, breakPointsAddress[pos], 0);
        }
        else if (mode == 's' && dataRead[1] == 'i')
        {
            /// lets delete--disable--add the old instructions for all breakPoints
            int i;
            struct user_regs_struct regs;
            for (i = 0; i < numOfbreakPoints; i++)
            {
                if (ptrace(PTRACE_POKEDATA, pid, (void *)breakPointsAddress[i], (void *)oldInstructions[i]) == -1)
                    die("(pokedata ) %s", strerror(errno));
            }
            // skips the cu
            process_step(pid);
            if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
            {
                if (errno == ESRCH)
                {
                    /* System call was exit; so we need to end.  */
                    fprintf(stderr, "The program is Done, has finished.\n");
                    exit(regs.rdi);
                }
                die("%s", strerror(errno));
            }
            long currIns = regs.rip;

            while (currIns > g_text_end || currIns < g_text_start)
            {
                process_step(pid);
                struct user_regs_struct regs;
                if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
                {
                    if (errno == ESRCH)
                    {
                        /* System call was exit; so we need to end.  */
                        fprintf(stderr, "The program is Done, has finished.\n");
                        exit(regs.rdi);
                    }
                    die("%s", strerror(errno));
                }
            }
            disas(handle, currIns, textData);
            /// ADD all breakpoints back for the future
            for (i = 0; i < numOfbreakPoints; i++)
            {
                set_breakpoint(pid, breakPointsAddress[i], 0);
            }
        }
        else
        {
            fprintf(stderr, "This command does not exist. \n\n");
            exit(1);
        }
    }
}

/**
 * @brief the function mainit just makes all the tables that are needed, and calls the breakPointMainFun
 *
 * @param argcthe number of given arfuments
 * @param argv the array with all the arguments
 * @return int when the function ends well
 */
int main(int argc, char **argv)
{
    if (argc <= 1)
    {
        die("Not enough arguments: min_strace <program>: %d", argc);
    }
    char *filename = argv[1];
    // char **symTabNames;               // has the name for the symbols
    long unsigned int *symTabAddress; // has the addresses for the symbols
    char **symTabNames;
    symTabNames = (char **)malloc(sizeof(char *) * 100);

    symTabAddress = (long unsigned int *)malloc(sizeof(long unsigned int) * 100);

    int symSize = makeSymbolTable(filename, symTabNames, symTabAddress);

    breakPointMainFun(symTabNames, symTabAddress, argv, symSize, filename);
    return 1;
}
