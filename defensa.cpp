#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>
#include "ptrace.h"

using namespace std;

int main(int argc, char *argv[]){

    int child, ret;

    if(argc < 2){
        cout<<"Usage: defensa <file to exec> [params]"<<endl;
        return 0;
    }

    child = fork();
    if(child == 0){
        if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0){
            cout<<"ptrace: Error tracing "<<argv[1]<<endl;
            return 0;
        }
        cout<<"Program traced "<<argv[1]<<endl;
        if(argc > 2)        
            execl(argv[1], argv[2], NULL);
        else
            execl(argv[1], NULL);
        
    } else {
        int wait_status;
        int c = 0;
        wait(&wait_status);
        while(WIFSTOPPED(wait_status)){
            c++;
            if(ptrace(PTRACE_CONT,  child, 0, 0) < 0){
                cout<<"ptrace: Error cont"<<endl;
                //break;
            }
            cout<<"step: "<<c<<endl;
            wait(&wait_status);
            if(c == 70) break;

        }
        cout<<"Child not being traced "<<child<<endl;
    }
    return 0;
}
