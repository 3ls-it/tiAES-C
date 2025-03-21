//tiaes.c
//(c) 2023 2024 J Adams jfa63[at]duck[dot]com
//Released under the 2-clause BSD license.

/*
 * Usage: tiaes [e,d] <infile> <outfile>
 */

#ifdef BSD
    #include <readpassphrase.h>
#endif

#ifdef LINUX
    #include <bsd/readpassphrase.h>
#endif

#include "core.h"

#ifndef CRYPUTILS_H
    #define CRYPUTILS_H
    #include "cryputils.h"
#endif

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
    char* pwd = malloc(1024);
    if (pwd == NULL) {
        perror("Memory allocation error");
        return -1;
    }

    // Read passphrase
    readpassphrase("Passphrase: ", pwd, sizeof(pwd), 0);

    // Use the 256-bit hash of the passphrase as the key.
    // The SHA256() function takes a char* as input and returns
    // a unsigned char pointer.
    uchar* key =  SHA256(pwd);

    // Zero-out and deallocate pwd memory location
	memset(pwd, 0, 32*sizeof(pwd[0]));
    free(pwd);

    // Do key expansion
    ke(key);

    // Zero-out and deallocate key memory location.
    memset(key, 0, 32*sizeof(key[0]));
    free(key);

    // Do encrypt/decrypt
    if (*argv[1] == 'e') {
        cbcenc(argv[2], argv[3]);

    } else if (*argv[1] == 'd') {;
        cbcdec(argv[2], argv[3]);

    } else {
        // Zero out key schedule
        memset(w, 0, 60*4*sizeof(w[0][0]));
        printf("Incorrect args:\n Usage: tiaes [e,d] <infile> <outfile>\n");
    }

    return 0;
}
 
