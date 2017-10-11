#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

#define FREE_ADDR_COUNT 5
#define ARM_BL_MASK     0xeb000000
#define ARM_BL_CLEAR    0xebffffff
        
// TODO: Load this directly from binary
static long text[] =    {0xe92d4008,    // push {r3, lr}
                         0xe2433a23,    // sub  r3, r3, #143360 ; 0x23000
                         0xe3530a25,    // cmp  r3, #151552     ; 0x25000
                         0x9a000002,    // bls  1c <exit>
                         0xe49d3004,    // pop  {r3}            ; (ldr r3, [sp], #4)
                         0xe12fff33,    // blx  r3
                         0xe49df004,    // pop  {pc}            ; (ldr pc, [sp], #4)
                         0xe3a07001,    // mov  r7, #1
                         0xef000000};   // svc  0x00000000
                      
long get_bl_instr(ulong target, ulong pc) {
    long ret = 0;

    pc = pc + sizeof(long);
    ret = ((~(pc - target) >> 2) & ARM_BL_CLEAR) | ARM_BL_MASK;
    printf("%s instruction: 0x%lx, target 0x%lx, pc 0x%lx\n", __func__,ret, target, pc);
    return ret;
}        

bool find_free_addr(pid_t pid, ulong addr, long seg_size, size_t size, ulong *free_addr){
    int bytes_read = 0;
    long word = 0;
    int i = 0;
    size_t count = 0;
    size /= sizeof(word);

    printf("%s Enter pid %d addr 0x%lx seg_size 0x%lx size 0x%lx\n", __func__,
           pid, addr, seg_size, size);

    while(bytes_read < seg_size){
        word = ptrace(PTRACE_PEEKTEXT, pid, addr + bytes_read, NULL);
        if(word == -1){
            printf("%s Error ptrace PTRACE_PEEKTEXT pid %d addr 0xlx\n", __func__,
                    pid, addr + bytes_read);
            return false;
        }
        // printf("0x%lx:\t0x%lx\n", addr + bytes_read, word);
        bytes_read += sizeof(word);
        
        if(word == 0){
            count++;
        } else {
            count = 0;
        }
        if(count == (size)){
            *free_addr = (addr + bytes_read) - (count * sizeof(word));
            printf("%s Found empty addres space at 0x%lx\n", __func__, *free_addr);
            return true;
        }      
    }

    return false;
}

bool find_exec_addr(pid_t pid, long *addr_start, long *addr_end){
    FILE *fp;
    char filename[30];
    char line[850];
    char str[20];
    char perms[5];

    snprintf(filename, 30, "/proc/%d/maps", pid);
    fp = fopen(filename, "r");
    if(fp == NULL){
        printf("%s Error opening file %s\n", __func__, filename);
        return false;
    }
    while(fgets(line, 850, fp) != NULL){
        sscanf(line, "%lx-%lx %s %*s %s %*d", addr_start, addr_end, perms, str);
        if(strstr(perms, "x") != NULL){
            printf("%s Found address 0x%lx-0x%lx\n", __func__, *addr_start, *addr_end);
            return true;
        }
    }
    return false;
}

bool write_to_addr(pid_t pid, ulong addr,  long *text, long size){
    long byte_count = 0;
    long word;
    int i = 0;

    while(byte_count < size){
        word = ptrace(PTRACE_POKETEXT, pid, addr + byte_count, text[i++]); 
        if(word == -1){
            printf("%s Error ptrace PTRACE_POKETEXT failed, addr 0x%lx word 0x%lx\n",
                    __func__, addr + byte_count, text[i-1]);
            return false;
        }
        byte_count += sizeof(word);
    }
    return true;
}

void print_from_addr(pid_t pid, ulong addr, size_t size){
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

void detach_debugger(pid_t pid){
    printf("%s Detaching %d\n", __func__, pid);
    if(ptrace(PTRACE_DETACH,  pid, 0, 0) < 0){
        printf("%s ptrace: Error detach\n", __func__);
    }
}

bool find_heap_addr(pid_t pid, long *addr_start, long *addr_end){
    FILE *fp;
    char filename[30];
    char line[850];
    char str[100];
    char perms[5];

    snprintf(filename, 30, "/proc/%d/maps", pid);
    fp = fopen(filename, "r");
    if(fp == NULL){
        printf("%s Error opening file %s\n", __func__, filename);
        return false;
    }
    while(fgets(line, 850, fp) != NULL){
        sscanf(line, "%lx-%lx %*s %*s %*s %*d %s", addr_start, addr_end, str);
        if(strstr(str, "heap") != NULL){
            printf("%s Found address 0x%lx-0x%lx\n", __func__, *addr_start, *addr_end);
            return true;
        }
    }
    return false;
}

bool replace_vt_call(pid_t pid, ulong addr_start, ulong addr_end, ulong target_addr){
    int bytes_read = 0;
    long word = 0;
    size_t count = 0;
    bool success = false;
    ulong curr_addr = 0;
    ulong seg_size = addr_end - addr_start;
    ulong pattern[] = {0xe5933000,       // ldr     r3, [r3]
                       0xe2833000,       // add r3, r3, #
                       0xe5933000,       // ldr     r3, [r3]
                       0xe51b0000,       // ldr     r0, [fp, #]
                       0xe12fff33};      // blx     r3

    printf("%s Enter pid %d addr_start 0x%lx seg_size 0x%lx target 0x%lx\n", __func__,
           pid, addr_start, seg_size, target_addr);

    while(bytes_read < seg_size){
        curr_addr = addr_start + bytes_read;
        word = ptrace(PTRACE_PEEKTEXT, pid, curr_addr, NULL);
        if(word == -1){
            printf("%s Error ptrace PTRACE_PEEKTEXT pid %d addr 0xlx\n", __func__,
                    pid, curr_addr);
            return false;
        }

        if(word == pattern[count]){
            count++;
        } else if (count == 1 && ((word & 0xfffff000) == pattern[count])){
            count++;
        } else if(word  == pattern[count+1]){
            count += 2;
        } else if (count == 3 && (word & 0xffff0000) == pattern[count]){
            count++;
        } else {
            count = 0;
        }

        // printf("count %d | 0x%lx:\t0x%lx\n", count,  curr_addr, word);
        
        if(count == (sizeof(pattern)/sizeof(ulong))){
            printf("%s Found pattern at addres 0x%lx: 0x%lx\n", __func__,
                   curr_addr, word);
            count = 0;
            long instr = get_bl_instr(target_addr, curr_addr);
            printf("%s Target Addr 0x%lx Current Addr 0x%lx > Instr: 0x%lx\n", __func__,
                   target_addr, curr_addr, instr);
            if(!write_to_addr(pid, curr_addr,  &instr, sizeof(instr))){
                printf("%s Failed to write to address 0x%lx\n", __func__, curr_addr);
                return false;                
            }
            success = true;
        }    

        bytes_read += sizeof(word);
    }
    if(!success){
        printf("%s Not match found\n", __func__);
    }
    return success;
}

void start_debugger(int pid, char* program){
    int wait_status;
    int c = 0;
    ulong free_addr;
    ulong addr_start, addr_end;
    
    printf("%s: Start debugger\n", __func__);
    wait(&wait_status);
    if(!WIFSTOPPED(wait_status)){
        printf("%s Program stoped %s %d\n", __func__, program, pid);
    }

    if(!find_exec_addr(pid, &addr_start, &addr_end)){
        printf("%s Failed to find exec address %s %d\n", __func__, program, pid);
        detach_debugger(pid);
        return;
    }
    
    if(!find_free_addr(pid, addr_start, addr_end - addr_start, sizeof(text), &free_addr)){
        printf("%s Failed to find free address %s %d start 0x%lx end 0x%lx \n",
               __func__, program, pid, addr_start, addr_end);
        detach_debugger(pid);
        return;
    }

    if(!write_to_addr(pid, free_addr, text, sizeof(text))){
        printf("%s Failed to write to address 0x%lx pid %d\n", __func__, free_addr, pid);
        detach_debugger(pid);
        return;
    }

    print_from_addr(pid, free_addr, sizeof(text));
    
    if(!replace_vt_call(pid, addr_start, addr_end, free_addr)){
        printf("%s Failed to replace vt call pid %d\n", __func__, pid);
        detach_debugger(pid);
        return;
    }

    detach_debugger(pid);
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
