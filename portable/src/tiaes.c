//tiaes.c
//(c) 2023 2024 J Adams jfa63[at]duck[dot]com
//Released under the 2-clause BSD license.

/*
 * Usage: tiaes [e,d] <infile> <outfile>
 */

#include "core.h"

#define BUFSIZE 1024


/* declaring external fuction ke() */
extern void ke(uchar*);


int
main(int argc, char* argv[])
{
    //arg checks
    if (argc != 4) {
        printf("Usage: tiaes [e,d] <infile> <outfile>\n");
        return -1;
    }

    // Allocate memory for passphrase
    char* pwd = malloc(BUFSIZE);
    if (pwd == NULL) {
        perror("Memory allocation error");
        return -1;
    }

    // Do encrypt/decrypt
    if (*argv[1] == 'e') {
        // Allocate memory for second passphrase
        char* pwd2 = malloc(BUFSIZE);
        if (pwd2 == NULL) {
            perror("Memory allocation error");
            return -1;
        }

        // Read passphrase
        readpassphrase("Enter passphrase: ", pwd, BUFSIZE, 0);
        readpassphrase("Enter passphrase again: ", pwd2, BUFSIZE, 0);

		if (strcmp(pwd, pwd2) != 0 ) {
		    printf("Passphrases do not match");
			printf("\n");
			exit(1);
		} 

        // Use the 256-bit hash of the passphrase as the key.
        // The SHA256() function takes a char* as input and returns
        // a unsigned char pointer.
        uchar* key =  SHA256(pwd);

        // Zero-out and deallocate pwd memory location
        explicit_bzero(pwd, BUFSIZE);
        free(pwd);
        explicit_bzero(pwd2, BUFSIZE);
        free(pwd2);

        // Do key expansion
        ke(key);

        // Zero-out and deallocate key memory location.
        explicit_bzero(key, KEY_SIZE);
        free(key);

        cbcenc(argv[2], argv[3]);

    } else if (*argv[1] == 'd') {;
        // Read passphrase
        readpassphrase("Enter passphrase: ", pwd, BUFSIZE, 0);

        // Use the 256-bit hash of the passphrase as the key.
        // The SHA256() function takes a char* as input and returns
        // a unsigned char pointer.
        uchar* key =  SHA256(pwd);

        // Zero-out and deallocate pwd memory location
        explicit_bzero(pwd, BUFSIZE);
        free(pwd);

        // Do key expansion
        ke(key);

        // Zero-out and deallocate key memory location.
        explicit_bzero(key, KEY_SIZE);
        free(key);
        cbcdec(argv[2], argv[3]);

    } else {
        // Zero out key schedule
        explicit_bzero(w, SCHEDULE_SIZE);
        printf("Incorrect args:\n Usage: tiaes [e,d] <infile> <outfile>\n");
    }

    return 0;
}
 
