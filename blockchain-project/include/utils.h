#ifndef UTILS_H
#define UTILS_H

#include <openssl/ec.h>

#define PUB_SIZE 128
#define PRV_SIZE 256
#define SIG_SIZE 128
#define HASH_SIZE 64

int base64_encode(const unsigned char *input, size_t input_len, char *output, size_t output_len);
int base64_decode(const char *input, unsigned char *output, size_t output_len);
int generate_keys(char *private_key, size_t private_key_len, char *public_key, size_t public_key_len);
EC_KEY* load_private_key(const char *private_key);
EC_KEY* load_public_key(const char *public_key);
int sign_message(const char *private_key, const char *message, char *signature, size_t signature_len);
int verify_signature(const char *public_key, const char *message, const char *signature);

#endif // UTILS_H