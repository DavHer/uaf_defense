#include <iostream>
#include <unistd.h>

using namespace std;

class Padre{
protected:
    int a;

public:
    Padre(int a){
        this->a = a;
    }
    virtual void caminar(){
        cout<<"Padre camina"<<endl;
    }
    virtual void hablar(){
        cout<<"Padre habla"<<endl;
    }
};

class Hijo: public Padre{
protected:
        int b;

public:
    Hijo(int a, int b):Padre(a){
        this->b = b;
    }
    void caminar(){
        cout<<"Hijo camina"<<endl;
    }
    void hablar(){
        cout<<"Hijo camina"<<endl;
    }
};

void addrSeg(){
    extern char etext;
    extern char edata;
    extern char end;

    printf("etext: %p\n", &etext);
    printf("edata: %p\n", &edata);
    printf("end: %p\n", &end);
}

void check(){
    int r3;
    asm("mov %0, r3" : "=r"(r3) :);
    if(r3 >= 0x23000 && r3 <= 0x48000){
        asm("mov r7, #1" ::);
        asm("svc #0" ::);
        asm("mov r3, r3" ::);
        _exit(0); 
    }
}

int main(){
    Padre *hijo = new Hijo(4, 7);
    hijo->caminar();
    hijo->hablar();
    Padre *padre = new Padre(3);
    padre->caminar();
    padre->hablar();

    while(1){
        sleep(2);
        cout<<"Durmiendo..."<<endl;
    }
    return 0;
}
