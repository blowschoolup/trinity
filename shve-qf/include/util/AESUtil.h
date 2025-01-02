//
// Created by ighxiy on 23-11-23.
//

#ifndef SHVE_CPLUS_AESUTIL_H
#define SHVE_CPLUS_AESUTIL_H

#include <openssl/evp.h>

typedef uint32_t uint32;
typedef uint8_t uint8;

/** Supported AES cipher/block mode combos */
enum my_aes_opmode {
    my_aes_128_ecb,
    my_aes_192_ecb,
    my_aes_256_ecb,
    my_aes_128_cbc,
    my_aes_192_cbc,
    my_aes_256_cbc,
    my_aes_128_cfb1,
    my_aes_192_cfb1,
    my_aes_256_cfb1,
    my_aes_128_cfb8,
    my_aes_192_cfb8,
    my_aes_256_cfb8,
    my_aes_128_cfb128,
    my_aes_192_cfb128,
    my_aes_256_cfb128,
    my_aes_128_ofb,
    my_aes_192_ofb,
    my_aes_256_ofb
};

/* If bad data discovered during decoding */
#define MY_AES_BAD_DATA -1

static const EVP_CIPHER *aes_evp_type(const my_aes_opmode mode) {
    switch (mode) {
        case my_aes_128_ecb:
            return EVP_aes_128_ecb();
        case my_aes_128_cbc:
            return EVP_aes_128_cbc();
        case my_aes_128_cfb1:
            return EVP_aes_128_cfb1();
        case my_aes_128_cfb8:
            return EVP_aes_128_cfb8();
        case my_aes_128_cfb128:
            return EVP_aes_128_cfb128();
        case my_aes_128_ofb:
            return EVP_aes_128_ofb();
        case my_aes_192_ecb:
            return EVP_aes_192_ecb();
        case my_aes_192_cbc:
            return EVP_aes_192_cbc();
        case my_aes_192_cfb1:
            return EVP_aes_192_cfb1();
        case my_aes_192_cfb8:
            return EVP_aes_192_cfb8();
        case my_aes_192_cfb128:
            return EVP_aes_192_cfb128();
        case my_aes_192_ofb:
            return EVP_aes_192_ofb();
        case my_aes_256_ecb:
            return EVP_aes_256_ecb();
        case my_aes_256_cbc:
            return EVP_aes_256_cbc();
        case my_aes_256_cfb1:
            return EVP_aes_256_cfb1();
        case my_aes_256_cfb8:
            return EVP_aes_256_cfb8();
        case my_aes_256_cfb128:
            return EVP_aes_256_cfb128();
        case my_aes_256_ofb:
            return EVP_aes_256_ofb();
        default:
            return nullptr;
    }
}



/**
  Creates required length of AES key,
  Input key size can be smaller or bigger in length, we need exact AES key
  size.
  @param [out] rkey Output key
  @param key Input key
  @param key_length input key length
*/
void my_aes_create_key(const unsigned char *key, uint key_length, uint8 *rkey);


int my_aes_decrypt(const unsigned char *source, uint32 source_length,
                   unsigned char *dest, const unsigned char *key,
                   uint32 key_length, enum my_aes_opmode mode,
                   const unsigned char *iv, bool padding);




int my_aes_encrypt(const unsigned char *source, uint32 source_length,
                   unsigned char *dest, const unsigned char *key,
                   uint32 key_length, enum my_aes_opmode mode,
                   const unsigned char *iv, bool padding);


int my_rand_buffer(unsigned char *buffer, size_t buffer_size);


//----------------------------below is aes-cmac

extern unsigned char const_Rb[16];

void leftshift_onebit(const unsigned char *input,unsigned char *output);

inline void xor_128(const unsigned char *a, const unsigned char *b, unsigned char *out){
    out[0] = a[0] ^ b[0];
    out[1] = a[1] ^ b[1];
    out[2] = a[2] ^ b[2];
    out[3] = a[3] ^ b[3];
    out[4] = a[4] ^ b[4];
    out[5] = a[5] ^ b[5];
    out[6] = a[6] ^ b[6];
    out[7] = a[7] ^ b[7];
    out[8] = a[8] ^ b[8];
    out[9] = a[9] ^ b[9];
    out[10] = a[10] ^ b[10];
    out[11] = a[11] ^ b[11];
    out[12] = a[12] ^ b[12];
    out[13] = a[13] ^ b[13];
    out[14] = a[14] ^ b[14];
    out[15] = a[15] ^ b[15];}

//inline void padding ( const unsigned char *lastb, unsigned char *pad, int length ){
//    /* original last block */
////    for (int j=0; j<16; j++ ) {
////        if ( j < length ) {
////            pad[j] = lastb[j];
////        } else if ( j == length ) {
////            pad[j] = 0x80;
////        } else {
////            pad[j] = 0x00;
////        }
////    }
//
//    for(int j=0;j<length;++j)
//        pad[j] = lastb[j];
//    pad[length] = 0x80;
//    for(int j=length+1;j<16;++j)
//        pad[j] = 0x00;
//}

//promise the in key len is 16, use my_aes_create_key to create legal key first
void generate_subkey(unsigned char *key, unsigned char *K1, unsigned char *K2);

//promise the in key len is 16, use my_aes_create_key to create legal key first
void AES_CMAC ( unsigned char *key, unsigned char *input, int input_len, char *mac );

//promise the in key len is 16, use my_aes_create_key to create legal key first
void AES_CMAC_WITH_PRE_SUBKEY (unsigned char* key,unsigned char* K1,unsigned char* K2, unsigned char* input, int input_len, char* mac);

#endif //SHVE_CPLUS_AESUTIL_H
