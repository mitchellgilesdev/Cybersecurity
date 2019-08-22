/* bn_sample.c */
#include <stdio.h>
#include <openssl/bn.h>
#include "math.h"
#include <openssl/sha.h>

#define NBITS 256

void printBN(char *msg, BIGNUM *a) {
/* Use BN_bn2hex(a) for hex string
* Use BN_bn2dec(a) for decimal string */
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main() {


    //A=2791
    //B=8507
    //E=4617
    //SHA-1

    //Alice will send A and g^a

    //  g=2879
    //  N=9929
    //  shared key?
    // Alice secret value a = 9.    g^a mod N send to eve
    // Bob secret value b = 6       g^b mod N send to eve
    // Eve value c = 5

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *g = BN_new();
    BIGNUM *N = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *A = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *B = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *C = BN_new();
    BIGNUM *k1 = BN_new();
    BIGNUM *k2 = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *res = BN_new();
    BIGNUM *res2 = BN_new();
    BIGNUM *ab = BN_new();

    BN_hex2bn(&e,"40F");
    BN_hex2bn(&N,"9DD7BE17C49CA5");

    BN_mod_inverse(res,e,N,ctx);
    printBN("The inverse is:",res);



    long input = 361448502791;
    unsigned char str[] ="361448502791";
//    unsigned char* str = (unsigned char*)(&input);
    int len = sizeof(str);

    unsigned char *outStr = calloc(32, 1);

    SHA1(str, len, outStr);

    for (int i = 0; i < 32; ++i) {
        printf("%X",outStr[i]);

    }

    printf("\n");

    long result = *((long*) outStr);
    printf("%ld\n",result);

    unsigned char string[] = "361448502791";
    int length = sizeof(string);

    unsigned char *outputString = calloc(32,1);
    SHA1(string,length,outputString);
    long results2 = *((long*) outputString);
    printf("%ld\n",results2);



    for (int i = 0; i < len; ++i) {
        printf("%d: %d\n", i, outStr[i]);
    }



    /*
    BN_dec2bn(&g, "2879");
    BN_dec2bn(&N, "9929");
    BN_dec2bn(&a, "9");
    BN_dec2bn(&b, "6");
    BN_dec2bn(&c, "5");

    //Alice sends Eve A=g^a mod N
    BN_mod_exp(A, g, a, N, ctx);

    //Bob sends Eve B=g^b mod N
    BN_mod_exp(B, g, b, N, ctx);

    //Eve sends bob and alice C = g^c mod N
    BN_mod_exp(C, g, c, N, ctx);

    //Eve computes k1 and k2
    BN_mod_exp(k1, A, c, N, ctx);
    printBN("EVE's k1", k1);
    BN_mod_exp(k2, B, c, N, ctx);
    printBN("EVE's k2:", k2);

    //Alice computes s
    BN_mod_exp(s, C, a, N, ctx);
    printBN("Alice's S:", s);

    //Bob computes s
    BN_mod_exp(res, C, b, N, ctx);
    printBN("Bob's S:", res);
*/
    /*
    BN_mul(ab,a,b,ctx);
    BN_mod_exp(res,g,ab,N,ctx);
    printBN("the check is:",res);
    */























//    BN_CTX *ctx = BN_CTX_new();
//
//    //two 'large' primes
//    BIGNUM *p = BN_new();
//    BIGNUM *q = BN_new();
//    BIGNUM *m = BN_new();
//    BIGNUM *m2 = BN_new();
//    BIGNUM *res = BN_new();
//    BIGNUM *res2 = BN_new();
//    BIGNUM *cipherText = BN_new();
//    BIGNUM *signature = BN_new();
//
//    //hex string
//    char msg[] = "4c61756e63682061206d6973736c65"; //Launch a Missle.
//    char msg2[] = "49206f776520796f75202433303030";
//    //hex string to BN
//    BN_hex2bn(&m, msg);
//    BN_hex2bn(&m2, msg2);
//
//    // (e,n) is the public key , d is the private key.
//    BIGNUM *e = BN_new();
//    BIGNUM *n = BN_new();
//    BIGNUM *d = BN_new();
//
//    //init variables
//    //  BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
//    //  BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
//    BN_hex2bn(&e, "010001");
//    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
//    //  BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
//    BN_hex2bn(&signature, "345B2AD16ED459EC90E92C4402384CF126CEE0693DB3CEAA5E1165CC02FA4F0F");
//    //  BN_hex2bn(&cipherText, "24C89C26F6DA860963AF6A6CC6335ED8176A71BADF4771C7726D09E66A6BE4AB");
//
//    /*
//    // multiply p and q and store in n
//    BN_mul(n, p, q, ctx);
//    printBN(" n = p * q = ", n);
//    */
//
//    /*
//    //encode plaintext
//    BN_mod_exp(res, m, e, n, ctx);
//    printBN("The ciphertext is:", res);
//    */
//
//    //decode to hex
//    // BN_mod_exp(res2, cipherText, d, n, ctx);
//    // printBN("The decoded cipherText is:", res2);
//
//    /*
//    // generate signature
//    BN_mod_exp(res, m, d, n, ctx);
//    printBN("The signature is: ", res);
//
//    BN_mod_exp(res2, m2, d, n, ctx);
//    printBN("The signature is: ", res2);
//    */
//
//    BN_mod_exp(res,signature,e,n,ctx);
//    printBN("Message is:",res);
//
//    // n = p^q mod e
//    // BN_mod_exp(n, p, q, e, ctx);
//    // printBN("p^q mod e = ", n);
//

    return 0;
}

