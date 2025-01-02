//
// Created by ighxiy on 23-11-23.
//

#ifndef SHVE_CPLUS_AESUTIL_H
#define SHVE_CPLUS_AESUTIL_H

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>

typedef uint32_t uint32;
typedef uint8_t uint8;
#define MAX_AES_KEY_LENGTH 256

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
void my_aes_create_key(const unsigned char *key, uint key_length, uint8 *rkey) {
    if(key_length==16){
        memcpy(rkey,key,16);
        return;
    }
    const uint key_size = 16;
    uint8 *rkey_end;                         /* Real key boundary */
    uint8 *ptr;                              /* Start of the real key*/
    const uint8 *sptr;                       /* Start of the working key */
    const uint8 *key_end = key + key_length; /* Working key boundary*/

    rkey_end = rkey + key_size;

    memset(rkey, 0, 16); /* Set initial key  */

    if(key_length<16){
        for (ptr = rkey, sptr = key; ptr < rkey_end; ptr++, sptr++) {
            if (sptr == key_end)
                sptr = key;
            *ptr ^= *sptr;
        }
    }
    else{
        for (ptr = rkey, sptr = key; sptr < key_end; ptr++, sptr++) {
            if (ptr == rkey_end) /*  Just loop over tmp_key until we used all key */
                ptr = rkey;
            *ptr ^= *sptr;
        }
    }
}


int my_aes_decrypt(const unsigned char *source, uint32 source_length,
                   unsigned char *dest, const unsigned char *key,
                   uint32 key_length, enum my_aes_opmode mode,
                   const unsigned char *iv, bool padding) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX stack_ctx;
  EVP_CIPHER_CTX *ctx = &stack_ctx;
#else  /* OPENSSL_VERSION_NUMBER < 0x10100000L */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
    const EVP_CIPHER *cipher = aes_evp_type(mode);
    int u_len, f_len;

    /* The real key to be used for decryption */
//    unsigned char rkey[MAX_AES_KEY_LENGTH / 8];
//    my_aes_create_key(key, key_length, rkey);

    if (key_length!=16 || !ctx || !cipher || (EVP_CIPHER_iv_length(cipher) > 0 && !iv))
        return MY_AES_BAD_DATA;

    if (!EVP_DecryptInit(ctx, aes_evp_type(mode), key, iv))
        goto aes_error;                                              /* Error */
    if (!EVP_CIPHER_CTX_set_padding(ctx, padding)) goto aes_error; /* Error */
    if (!EVP_DecryptUpdate(ctx, dest, &u_len, source, source_length))
        goto aes_error; /* Error */
    if (!EVP_DecryptFinal_ex(ctx, dest + u_len, &f_len))
        goto aes_error; /* Error */

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_cleanup(ctx);
#else  /* OPENSSL_VERSION_NUMBER < 0x10100000L */
    EVP_CIPHER_CTX_free(ctx);
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

    return u_len + f_len;

    aes_error:
    /* need to explicitly clean up the error if we want to ignore it */
    ERR_clear_error();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_cleanup(ctx);
#else  /* OPENSSL_VERSION_NUMBER < 0x10100000L */
    EVP_CIPHER_CTX_free(ctx);
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
    return MY_AES_BAD_DATA;
}




int my_aes_encrypt(const unsigned char *source, uint32 source_length,
                   unsigned char *dest, const unsigned char *key,
                   uint32 key_length, enum my_aes_opmode mode,
                   const unsigned char *iv, bool padding) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX stack_ctx;
  EVP_CIPHER_CTX *ctx = &stack_ctx;
#else  /* OPENSSL_VERSION_NUMBER < 0x10100000L */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
    const EVP_CIPHER *cipher = aes_evp_type(mode);
    int u_len, f_len;
    /* The real key to be used for encryption */
//    unsigned char rkey[MAX_AES_KEY_LENGTH / 8];
//    my_aes_create_key(key, key_length, rkey);

    if (key_length!=16 || !ctx || !cipher || (EVP_CIPHER_iv_length(cipher) > 0 && !iv))
        return MY_AES_BAD_DATA;

    if (!EVP_EncryptInit(ctx, cipher, key, iv)) goto aes_error;   /* Error */
    if (!EVP_CIPHER_CTX_set_padding(ctx, padding)) goto aes_error; /* Error */
    if (!EVP_EncryptUpdate(ctx, dest, &u_len, source, source_length))
        goto aes_error; /* Error */

    if (!EVP_EncryptFinal(ctx, dest + u_len, &f_len)) goto aes_error; /* Error */

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_cleanup(ctx);
#else  /* OPENSSL_VERSION_NUMBER < 0x10100000L */
    EVP_CIPHER_CTX_free(ctx);
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
    return u_len + f_len;

    aes_error:
    /* need to explicitly clean up the error if we want to ignore it */
    ERR_clear_error();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_cleanup(ctx);
#else  /* OPENSSL_VERSION_NUMBER < 0x10100000L */
    EVP_CIPHER_CTX_free(ctx);
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
    return MY_AES_BAD_DATA;
}


int my_rand_buffer(unsigned char *buffer, size_t buffer_size) {
    int rc;
    rc = RAND_bytes(buffer, (int)buffer_size);
    if (!rc) {
        ERR_clear_error();
        return 1;
    }
    return 0;
}


//----------------------------below is aes-cmac

unsigned char const_Rb[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87
};


void leftshift_onebit(const unsigned char *input,unsigned char *output){
    unsigned char overflow = 0;
    unsigned char stor[16]{};
    memcpy(stor,input,16);
    for (int i=15; i>=1; i-=2 ) {
        output[i] = input[i] << 1;
        output[i] |= overflow;
        overflow = (input[i] & 0x80)?1:0;

        output[i-1] = input[i-1] << 1;
        output[i-1] |= overflow;
        overflow = (input[i-1] & 0x80)?1:0;
    }
}

inline void xor_128(const unsigned char *a, const unsigned char *b, unsigned char *out){
//    for (int i=0;i<15; i+=2){//16 total
//        out[i] = a[i] ^ b[i];
//        out[i+1] = a[i+1] ^ b[i+1];
//    }
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
    out[15] = a[15] ^ b[15];
}


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
void generate_subkey(unsigned char *key, unsigned char *K1, unsigned char *K2){
    unsigned char L[16];
    unsigned char Z[16]{};
    unsigned char tmp[16];

    my_aes_encrypt(Z,16,L,key,16,my_aes_128_ecb, nullptr, false);

    if ( (L[0] & 0x80) == 0 ) { /* If MSB(L) = 0, then K1 = L << 1 */
        leftshift_onebit(L,K1);
    } else {    /* Else K1 = ( L << 1 ) (+) Rb */
        leftshift_onebit(L,tmp);
        xor_128(tmp,const_Rb,K1);
    }

    if ( (K1[0] & 0x80) == 0 ) {
        leftshift_onebit(K1,K2);
    } else {
        leftshift_onebit(K1,tmp);
        xor_128(tmp,const_Rb,K2);
    }
}

//promise the in key len is 16, use my_aes_create_key to create legal key first
void AES_CMAC ( unsigned char *key, unsigned char *input, int input_len, char *mac ){
    unsigned char X[16]{},Y[16], M_last[16], padded[16];
    unsigned char K1[16], K2[16];

//    unsigned char rkey[16]{};
//    my_aes_create_key(key,strlen(reinterpret_cast<const char *>(key)),rkey);

    generate_subkey(key,K1,K2);

    int n = (input_len+15) / 16 - 1;       /* n is the number of complete block rounds */

    if ( (input_len%16) == 0 ) {/* last block is a complete block */
        xor_128(&input[16*n],K1,M_last);
    }
    else{/* last block is not complete block */
        //        padding(&input[16*(n-1)],padded,input_len%16);
        int rem=input_len%16;
        unsigned char * lastb=&input[16*n];
        for(int j=0;j<rem;++j)
            padded[j] = lastb[j];
        padded[rem] = 0x80;
        for(int j=rem+1;j<16;++j)
            padded[j] = 0x00;
        xor_128(padded,K2,M_last);
    }

    for (int i=0; i<n; i++ ) {
        xor_128(X,&input[16*i],Y); /* Y := Mi (+) X  */
        my_aes_encrypt(Y, 16, X, key, 16, my_aes_128_ecb, nullptr, false);/* X := AES-128(KEY, Y); */
    }

    xor_128(X,M_last,Y);
    my_aes_encrypt(Y,16,X,key,16,my_aes_128_ecb, nullptr, false);
    for (int i=0; i<16; i++ ) {
        mac[i] = X[i];
    }
}


//promise the in key len is 16, use my_aes_create_key to create legal key first
void AES_CMAC_WITH_PRE_SUBKEY (unsigned char* key,unsigned char* K1,unsigned char* K2, unsigned char* input, int input_len, char* mac){
    unsigned char X[16]{},Y[16], M_last[16], padded[16];
    int n = (input_len+15) / 16 - 1;       /* n is the number of complete block rounds */

    if ( (input_len%16) == 0 ) {/* last block is a complete block */
        xor_128(&input[16*n],K1,M_last);
    }
    else{/* last block is not complete block */
        //        padding(&input[16*(n-1)],padded,input_len%16);
        int rem=input_len%16;
        unsigned char * lastb=&input[16*n];
        for(int j=0;j<rem;++j)
            padded[j] = lastb[j];
        padded[rem] = 0x80;
        for(int j=rem+1;j<16;++j)
            padded[j] = 0x00;
        xor_128(padded,K2,M_last);
    }

    for (int i=0; i<n; i++ ) {
        xor_128(X,&input[16*i],Y); /* Y := Mi (+) X  */
        my_aes_encrypt(Y, 16, X, key, 16, my_aes_128_ecb, nullptr, false);/* X := AES-128(KEY, Y); */
    }

    xor_128(X,M_last,Y);
    my_aes_encrypt(Y,16,X,key,16,my_aes_128_ecb, nullptr, false);
    for (int i=0; i<16; i++ ) {
        mac[i] = X[i];
    }
}

#endif //SHVE_CPLUS_AESUTIL_H
