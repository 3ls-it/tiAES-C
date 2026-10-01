//tests.c

#include <stdio.h>
#include <openssl/rand.h>
#include "core.h"

#ifndef CRYPUTILS_H
#define CRYPUTILS_H
#include "cryputils.h"
#endif

/*
// 256-bit FIPS key for KeyExpansion
uchar ekey256[] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                   0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                   0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                   0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};

// Test state vector from FIPS 197 for KeyExpansion
block st = {{0x32, 0x88, 0x31, 0xe0},
            {0x43, 0x5a, 0x31, 0x37},
            {0xf6, 0x30, 0x98, 0x07},
            {0xa8, 0x8d, 0xa2, 0x34}};
*/

// 256-bit FIPS key for encryption
// 00 01 02 03 04 05 06 07
// 08 09 0a 0b 0c 0d 0e 0f
// 10 11 12 13 14 15 16 17
// 18 19 1a 1b 1c 1d 1e 1f
uchar ckey256[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                   0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                   0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                   0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

// Test plain text state vector from FIPS 197 for encryption
// 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
block st = {{0x00, 0x44, 0x88, 0xcc},
            {0x11, 0x55, 0x99, 0xdd},
            {0x22, 0x66, 0xaa, 0xee},
            {0x33, 0x77, 0xbb, 0xff}};



void
print_test(block arr)
{
    for (int j=0; j<4; ++j) {
        for (int i=0; i<4; ++i) {
            printf("%x ", arr[i][j]);
        }
    }
}


void
encr_test()
{
    int c,r,rd = 0;
    printf("Rounds %d\n", nr);
    printf("round[0].input\n");
    print_test(st);
    printf("\n");

    /* AddRoundKey()  (column of state) xor (row of RoundKey) */
    //round number 0
    printf("round[0].k_schd\n");
    for (r=0; r<4; r++) {
        for (c=0; c<4; c++) {
            st[c][r] ^= w[rd*4+r][c];
            printf("%x ", w[rd*4+r][c]);
        }
    }
    printf("\n");

    //rounds 1 to nr-1
    for (rd=1; rd<nr; rd++) {
        printf("round[%d].start\n", rd);
        print_test(st);
        printf("\n");

        /*SubBytes()*/
        for (r=0; r<4; r++) {
            for (c=0; c<4; c++) {
                st[r][c] = sbox[st[r][c]];
            }
        }
        printf("round[%d].s_box\n", rd);
        print_test(st);
        printf("\n");

        /* ShiftRows() */
        //row 1, no rotation
        ns[0][0] = st[0][0];
        ns[0][1] = st[0][1];
        ns[0][2] = st[0][2];
        ns[0][3] = st[0][3];
        //row 2, 1 rotation
        ns[1][0] = st[1][1];
        ns[1][1] = st[1][2];
        ns[1][2] = st[1][3];
        ns[1][3] = st[1][0];
        //row 3, 2 rotations
        ns[2][0] = st[2][2];
        ns[2][1] = st[2][3];
        ns[2][2] = st[2][0];
        ns[2][3] = st[2][1];
        //row 4, 3 rotations
        ns[3][0] = st[3][3];
        ns[3][1] = st[3][0];
        ns[3][2] = st[3][1];
        ns[3][3] = st[3][2];
        cpyns_st();
        printf("round[%d].s_row\n", rd);
        print_test(st);
        printf("\n");

        /* MixColumns() */
        for (c=0; c<4; c++) {
            ns[0][c] = m2[st[0][c]] ^ m3[st[1][c]] ^ st[2][c] ^ st[3][c];
            ns[1][c] = st[0][c] ^ m2[st[1][c]] ^ m3[st[2][c]] ^ st[3][c];
            ns[2][c] = st[0][c] ^ st[1][c] ^ m2[st[2][c]] ^ m3[st[3][c]];
            ns[3][c] = m3[st[0][c]] ^ st[1][c] ^ st[2][c] ^ m2[st[3][c]];
        }
        cpyns_st();
        printf("round[%d].m_col\n", rd);
        print_test(st);
        printf("\n");

        /* AddRoundKey() */
        //round rd
        printf("round[%d].k_schd\n", rd);
        for (r=0; r<4; r++) {
            for (c=0; c<4; c++) {
                st[c][r] ^= w[rd*4+r][c];
                printf("%x ", w[rd*4+r][c]);
            }
        }
        printf("\n");
    }//end rounds nr-1 to 1

    /* SubBytes() */
    for (r=0; r<4; r++) {
        for (c=0; c<4; c++) {
            st[r][c] = sbox[st[r][c]];
        }
    }
    printf("round[%d].s_box\n", rd);
    print_test(st);
    printf("\n");

    /* ShiftRows() */
    //row 1, no rotation
    ns[0][0] = st[0][0];
    ns[0][1] = st[0][1];
    ns[0][2] = st[0][2];
    ns[0][3] = st[0][3];
    //row 2, 1 rotation
    ns[1][0] = st[1][1];
    ns[1][1] = st[1][2];
    ns[1][2] = st[1][3];
    ns[1][3] = st[1][0];
    //row 3, 2 rotations
    ns[2][0] = st[2][2];
    ns[2][1] = st[2][3];
    ns[2][2] = st[2][0];
    ns[2][3] = st[2][1];
    //row 4, 3 rotations
    ns[3][0] = st[3][3];
    ns[3][1] = st[3][0];
    ns[3][2] = st[3][1];
    ns[3][3] = st[3][2];
    cpyns_st();
    printf("round[%d].s_row\n", rd);
    print_test(st);
    printf("\n");

    /* AddRoundKey() */
    //round nr
    printf("round[%d].k_schd\n", rd);
    for (r=0; r<4; r++) {
        for (c=0; c<4; c++) {
            st[c][r] ^= w[rd*4+r][c];
            printf("%x ", w[rd*4+r][c]);
        }
    }
    printf("\n");
    printf("round[%d].output\n", rd);
    print_test(st);
    printf("\n");
}//end encr_test()
 

void
gen_rand(unsigned char* buff)
{
    // Initialize the random number generator
    RAND_poll();

    // Generate 64byte random number
    if (RAND_bytes(buff, 64) != 1) {
        printf("Error generating random number.\n");
        // handle the error 
    }

}


void
get_iv()
{
    int i;
    uchar* rn = malloc(64);

    gen_rand(rn);

    // Display the random number in hex
    for (i = 0; i < 64; i++) {
        printf("%02x ", rn[i]);
    }
    printf("\n\n");
    
    uchar* hsh = SHA256(rn);
    explicit_bzero(rn, 64*sizeof(rn[0]));

    for (i = 0; i < 32; i++) {
        printf("%02x ", hsh[i]);
    }
    printf("\n");

    i = 0;
    for (int r=0; r<4; r++) {
        for (int c=0; c<4; c++) {
            iv[r][c] = hsh[i];
            i++;
        }
    }
    explicit_bzero(hsh, 32*sizeof(hsh[0]));
}


int
main(void)
{
    int sz;

    get_iv();
    // display iv
    printf("\n");
    for (int r=0; r<4; r++) {
        for (int c=0; c<4; c++) {
            printf("%02x", iv[r][c]);
        }
        printf("\n");
    }


    //uchar* key = SHA256("toblatheistobluff");
    //for (int i=0; i<32; ++i) {
    //    printf("%x ", key[i]);
    //}
    // Do key expansion
    //ke(key);
    //encr();
    //encr_test();

    // Print state
    //printf("Our output:\n");
    //print_test(st);
    //printf("\n");
    //printf("FIPS output:\n");
    //printf("8e a2 b7 ca 51 67 45 bf ea fc 49 90 4b 49 60 89\n");

    return 0;
}
 
