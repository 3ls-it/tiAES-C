//Fips 197 Xtime
//xtime_cli.c

#include <stdio.h>
#include "gfmath.h"


int main() {
    uint a;
    printf("Enter: ");
    scanf("%u",&a);
    a = xtime(a);
    printf("%u\n",a);
    return 0;
}
