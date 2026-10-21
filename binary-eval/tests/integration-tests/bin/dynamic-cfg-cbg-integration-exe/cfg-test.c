#include <stdio.h>

__declspec(noinline) int calculate(int value){
    volatile int result = 0;

    for (int i = 0; i < value; i++)
    {
        if (i % 2 == 0){
            result += i;
        }
        else{
            result -= i;
        }
    }

    return result;
}

int main(void){
    printf("Result: %d\n", calculate(10));
    return 0;
}