//outputs the GF256 anti-log look-up table

#include "gfmath.h"

int main() {
	
	printf("Your alog table\n");
	printf("%d",1);
	printf("%c",',');
	
	uint t=1;
	for (uint i=2; i<=256; i++) {
		t=xtime3(t);
		printf("%d",t );
		printf("%c",',');
	}
	printf("%c",'\n');

}
