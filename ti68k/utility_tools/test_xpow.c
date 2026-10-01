//testing xpow	
#include "gfmath.h"

int main() {
	uchar b,e,c;
    printf("Enter base: ");
    scanf("%hhu",&b);
    printf("Enter exponent: ");
    scanf("%hhu",&e);
	c=xpow(b,e);
	printf("%hhu",c);
	printf("%c",'\n');
	return 0;
}
