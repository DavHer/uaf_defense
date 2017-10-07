#include <iostream>
#include <stdio.h>
#include <assert.h>
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
    extern char edata;
    int r3;
    asm("mov %0, r3" : "=r"(r3) :);
    printf("R3 = 0x%0x\n", r3);
    printf("edata: %p\n", &edata);
    if(r3 <= (int)&edata){
        cout<<"I am valid"<<endl;
    } else {
        cout<<"I am not valid"<<endl;
        assert(0);
    }
}

int main(){
    Padre *hijo = new Hijo(4, 7);
    hijo->caminar();
    hijo->hablar();
    Padre *padre = new Padre(3);
    padre->caminar();
    padre->hablar();

    check();

    /*while(1){
        sleep(2);
        cout<<"Durmiendo..."<<endl;
    }*/
    return 0;
}
