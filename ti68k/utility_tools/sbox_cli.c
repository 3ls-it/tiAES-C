///testing sbox()
#include "gfmath.h"


int main() {
    uchar n,s;
    printf("Enter an integer < 256:\n");
    scanf("%hhu",&n);
    s=sbox(n);
    printf("%hhu",s);
    printf("\n");
    return 0;
}
