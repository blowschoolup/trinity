#ifndef ECDH_FORWARD_SECURE_H
#define ECDH_FORWARD_SECURE_H

#include <vector>
#include <openssl/evp.h>

// Function to handle errors
void handleErrors();

// Function to derive a session key from a shared secret
std::vector<unsigned char> deriveSessionKey(const unsigned char *sharedSecret, size_t secretLen, size_t keyLen);

#endif // ECDH_FORWARD_SECURE_H