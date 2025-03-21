//Fips 197 xtime3
//xtime3_cli.c

#include <stdio.h>
#include "gfmath.h"


int main() {
    uint a;
    printf("Enter: ");
    scanf("%d",&a);
    a = xtime3(a);
    printf("%d\n",a);
    return 0;
}
