//xmult_cli.c
//Fips 197 xmult
#include <stdio.h>
#include "gfmath.h"

typedef unsigned int uint;


int main() {
    uint a,b,d;
    
    //get input
    printf("Enter first integer: ");
    scanf("%u",&a);
    printf("Enter second integer: ");
    scanf("%u",&b);
    //call xmult
    d = xmult_nt(a, b);
    printf("%u\n",d);

}
