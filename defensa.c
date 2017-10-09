#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#define FREE_ADDR_COUNT 5
#define ARM_BL_MASK     0xeb000000
#define ARM_BL_CLEAR    0xebffffff
        
/*
00010d08 <_Z5checkv>:
                e92d4800        push    {fp, lr}
   10d0c:       e2433a23        sub     r3, r3, #143360 ; 0x23000
   10d10:       e3530a25        cmp     r3, #151552     ; 0x25000
   10d14:       9a000000        bls     10d1c <_Z5checkv+0x14>
                e12fff33        blx     r3
                e8bd8800        pop     {fp, pc}
   10d18:       e12fff1e        bx      lr     
   10d20:       0xe3a07001      mov     r7, #1   
   10d24:       0xef000000      svc     0x00000000
*/

static long text[] = {0xe3530a23};
                      
long get_bl_instr(ulong target, ulong pc) {
    long ret = 0;

    pc = pc + sizeof(long);
    ret = ((~(pc - target) >> 2) & ARM_BL_CLEAR) | ARM_BL_MASK;
    printf("%s instruction: 0x%lx, target 0x%lx, pc 0x%lx\n", __func__,ret, target, pc);
    return ret;
}        

ulong find_free_addr(pid_t pid, ulong addr, long seg_size, size_t size){
    int bytes_read = 0;
    long word = 0;
    int i = 0;
    size_t count = 0;
    ulong free_addr = 0;


    while(bytes_read < seg_size){
        word = ptrace(PTRACE_PEEKTEXT, pid, addr + bytes_read, NULL);
        if(word == -1){
            printf("%s Error ptrace PTRACE_PEEKTEXT pid %d addr 0xlx\n", __func__,
                    pid, addr + bytes_read);
            return 0;
        }
        //printf("0x%lx:\t0x%lx\n", addr + bytes_read, word);
        bytes_read += sizeof(word);

        
if(word == 0){
            count++;
        } else {
            count = 0;
        }
        if(count == size){
            free_addr = (addr + bytes_read) - (count * sizeof(word));
            printf("%s Found empty addres space at 0x%lx\n", __func__, free_addr);
            break;
        }      
    }

    printf("%s Exit addr 0x%lx\n", __func__, free_addr);
    return free_addr;
}

ulong find_exec_addr(pid_t pid, size_t size){
    FILE *fp;
    char filename[30];
    char line[850];
    long addr_start, addr_end;
    char str[20];
    char perms[5];
    ulong free_addr;

    snprintf(filename, 30, "/proc/%d/maps", pid);
    fp = fopen(filename, "r");
    if(fp == NULL){
        printf("%s Error opening file %s\n", __func__, filename);
        return 0;
    }
    while(fgets(line, 850, fp) != NULL){
        sscanf(line, "%lx-%lx %s %*s %s %*d", &addr_start, &addr_end, perms, str);
        if(strstr(perms, "x") != NULL){
            printf("%s Found address 0x%lx-0x%lx\n", __func__, addr_start, addr_end);
            break;
        }
    }
    
    free_addr = find_free_addr(pid, addr_start, addr_end - addr_start, size);
    if(free_addr == 0){
        printf("%s Did not found valid address\n", __func__);
        return free_addr;
    }
    return free_addr;
}

void write_to_addr(pid_t pid, ulong addr,  long *text, long size){
    long byte_count = 0;
    long word;
    int i = 0;

    while(byte_count < size){
        word = ptrace(PTRACE_POKETEXT, pid, addr + byte_count, text[i++]); 
        if(word == -1){
            printf("%s Error ptrace PTRACE_POKETEXT failed, addr 0x%lx word 0x%lx\n",
                    __func__, addr + byte_count, text[i-1]);
            exit(1);
        }
        byte_count += sizeof(word);
    }
}

void read_from_addr(pid_t pid, ulong addr, size_t size){
    size_t bytes_read = 0;
    long word = 0;
    int i = 0;


    while(bytes_read < size){
        word = ptrace(PTRACE_PEEKTEXT, pid, addr + bytes_read, NULL);
        if(word == -1){
            printf("%s Error ptrace PTRACE_PEEKTEXT pid %d addr 0xlx\n", __func__,
                    pid, addr + bytes_read);
            break;
        }
        printf("%s 0x%lx:\t0x%lx\n", __func__, addr + bytes_read, word);
        bytes_read += sizeof(word);
    }
}

void start_debugger(int pid, char* program){
    int wait_status;
    int c = 0;
    ulong free_addr;
    
    printf("%s: Start debugger\n", __func__);
    wait(&wait_status);
    if(!WIFSTOPPED(wait_status)){
        printf("Program stoped %s %d\n", program, pid);
    }

    free_addr = find_exec_addr(pid, sizeof(text));
    write_to_addr(pid, free_addr, text, sizeof(text));
    read_from_addr(pid, free_addr, sizeof(text));
    printf("%s Detaching %d\n", __func__, pid);
    if(ptrace(PTRACE_DETACH,  pid, 0, 0) < 0){
        printf("%s ptrace: Error detach\n", __func__);
    }
    printf("%s: Exit debugger\n", __func__);
}

void start_program(char *program, char* params){
    if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0){
        printf("ptrace: Error tracing %s\n", program);
        return;
    }
    if(params)        
        execl(program, params, NULL);
    else
        execl(program, NULL);
}

int main(int argc, char *argv[]){

    int child, ret;

    get_bl_instr(0x108f4, 0x109dc);
    get_bl_instr(0x10b60, 0x1095c);
    get_bl_instr(0x00010d1c, 0x00010d14);
    return 0;
    if(argc < 2){
        printf("Usage: defensa <file to exec> [params]\n");
        return 0;
    }

    child = fork();
    if(child == 0){
        if(argc > 2) 
            start_program(argv[1], argv[2]);
        else
            start_program(argv[1], NULL);
    } else {
        start_debugger(child, argv[1]);
    }
    return 0;
}
