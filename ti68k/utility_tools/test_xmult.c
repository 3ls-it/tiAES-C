//testing xmult
#include "gfmath.h"

int main() {
	uchar a,b,c;
    printf("Enter first integer: ");
    scanf("%hhu",&a);
    printf("Enter second integer: ");
    scanf("%hhu",&b);
	c=xmult(a, b);
	printf("%hhu",c);
	printf("%c",'\n');
	return 0;
}
