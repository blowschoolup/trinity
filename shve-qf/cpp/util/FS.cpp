#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <iostream>
#include <vector>

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

std::vector<unsigned char> deriveSessionKey(const unsigned char *sharedSecret, size_t secretLen, size_t keyLen) {
    std::vector<unsigned char> sessionKey(keyLen);
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) handleErrors();

    if (EVP_PKEY_derive_init(pctx) <= 0) handleErrors();
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) handleErrors();
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, NULL, 0) <= 0) handleErrors();
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, sharedSecret, secretLen) <= 0) handleErrors();
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, (unsigned char *)"handshake data", 14) <= 0) handleErrors();
    if (EVP_PKEY_derive(pctx, sessionKey.data(), &keyLen) <= 0) handleErrors();

    EVP_PKEY_CTX_free(pctx);
    return sessionKey;
}

int main() {
    // Generate ephemeral keys for both parties
    EVP_PKEY *pkeyA = NULL, *pkeyB = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) handleErrors();

    if (EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(pctx, &pkeyA) <= 0) handleErrors();

    if (EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(pctx, &pkeyB) <= 0) handleErrors();

    EVP_PKEY_CTX_free(pctx);

    // Perform ECDH key exchange
    EVP_PKEY_CTX *ctxA = EVP_PKEY_CTX_new(pkeyA, NULL);
    if (!ctxA) handleErrors();

    if (EVP_PKEY_derive_init(ctxA) <= 0 ||
        EVP_PKEY_derive_set_peer(ctxA, pkeyB) <= 0) handleErrors();

    size_t secretLen;
    if (EVP_PKEY_derive(ctxA, NULL, &secretLen) <= 0) handleErrors();

    std::vector<unsigned char> sharedSecretA(secretLen);
    if (EVP_PKEY_derive(ctxA, sharedSecretA.data(), &secretLen) <= 0) handleErrors();

    EVP_PKEY_CTX_free(ctxA);

    // Derive session key from shared secret
    size_t keyLen = 32; // 256-bit session key
    std::vector<unsigned char> sessionKeyA = deriveSessionKey(sharedSecretA.data(), secretLen, keyLen);

    // Print session key
    std::cout << "Derived session key: ";
    for (unsigned char c : sessionKeyA) {
        printf("%02x", c);
    }
    std::cout << std::endl;

    // Clean up
    EVP_PKEY_free(pkeyA);
    EVP_PKEY_free(pkeyB);

    return 0;
}