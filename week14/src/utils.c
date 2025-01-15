#include <string.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "utils.h"

int base64_encode(const unsigned char *input, size_t input_len, char *output, size_t output_len) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);

    BIO_write(b64, input, input_len);
    (void)BIO_flush(b64);

    BUF_MEM *buffer_ptr;
    BIO_get_mem_ptr(mem, &buffer_ptr);

    if (buffer_ptr->length >= output_len) {
        BIO_free_all(b64);
        return -1;
    }

    memcpy(output, buffer_ptr->data, buffer_ptr->length);
    output[buffer_ptr->length] = '\0';

    BIO_free_all(b64);
    return 0;
}

int base64_decode(const char *input, unsigned char *output, size_t output_len) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new_mem_buf(input, -1);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);
    
    size_t length = BIO_read(b64, output, output_len);
    BIO_free_all(b64);
    return length;
}

int generate_keys(char *private_key, size_t private_key_len, char *public_key, size_t public_key_len) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!EC_KEY_generate_key(key)) {
        fprintf(stderr, "Error generating ECDSA key: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EC_KEY_free(key);
        return -1;
    }

    unsigned char private_key_buffer[PRV_SIZE];
    unsigned char *private_key_ptr = private_key_buffer;
    size_t private_buffer_len = i2d_ECPrivateKey(key, &private_key_ptr);
    if (private_buffer_len <= 0) {
        fprintf(stderr, "Error converting private key to DER: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EC_KEY_free(key);
        return -1;
    }
    base64_encode(private_key_buffer, private_buffer_len, private_key, private_key_len);

    unsigned char public_key_buffer[PUB_SIZE];
    unsigned char *public_key_ptr = public_key_buffer;
    size_t public_buffer_len = i2d_EC_PUBKEY(key, &public_key_ptr);
    if (public_buffer_len <= 0) {
        fprintf(stderr, "Error converting public key to DER: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EC_KEY_free(key);
        return -1;
    }
    base64_encode(public_key_buffer, public_buffer_len, public_key, public_key_len);

    EC_KEY_free(key);
    return 0;
}

EC_KEY* load_private_key(const char *private_key) {
    unsigned char private_key_der[PRV_SIZE];
    size_t private_key_len = base64_decode(private_key, private_key_der, sizeof(private_key_der));
    if (private_key_len <= 0) {
        return NULL;
    }
    unsigned const char *p = private_key_der;
    EC_KEY *key = d2i_ECPrivateKey(NULL, &p, private_key_len);
    if (!key) {
        fprintf(stderr, "Error loading private key from DER: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }
    return key;
}

EC_KEY* load_public_key(const char *public_key) {
    unsigned char public_key_der[PUB_SIZE];
    size_t public_key_len = base64_decode(public_key, public_key_der, sizeof(public_key_der));
    if (public_key_len <= 0) {
        return NULL;
    }
    unsigned const char *p = public_key_der;
    EC_KEY *key = d2i_EC_PUBKEY(NULL, &p, public_key_len);
    if (!key) {
        fprintf(stderr, "Error loading public key from DER: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }
    return key;
}

// int sign_message_standard(const char *private_key, const char *message, char *signature, size_t signature_len) {
//     EC_KEY *prv = load_private_key(private_key);
//     unsigned char hash[SHA256_DIGEST_LENGTH];
//     SHA256((unsigned char*)message, strlen(message), hash);

//     ECDSA_SIG *sig = ECDSA_do_sign(hash, SHA256_DIGEST_LENGTH, prv);
//     if (!sig) {
//         fprintf(stderr, "Error signing message: %s\n", ERR_error_string(ERR_get_error(), NULL));
//         return -1;
//     }

//     unsigned char sig_buffer[SIG_SIZE];
//     unsigned char *sig_ptr = sig_buffer;

//     size_t sig_buffer_len = i2d_ECDSA_SIG(sig, &sig_ptr);
//     base64_encode(sig_buffer, sig_buffer_len, signature, signature_len);

//     ECDSA_SIG_free(sig);
//     EC_KEY_free(prv);
//     return 0;
// }

int sign_message(const char *private_key, const char *message, char *signature, size_t signature_len) {
    EC_KEY *prv = load_private_key(private_key);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)message, strlen(message), hash);
    
    BIGNUM *k = BN_new();
    BN_set_word(k, 1);

    const EC_GROUP *group = EC_KEY_get0_group(prv);
    BIGNUM *r = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    EC_POINT *result_point = EC_POINT_new(group);

    EC_POINT_mul(group, result_point, k, NULL, NULL, ctx);
    EC_POINT_get_affine_coordinates_GFp(group, result_point, r, NULL, ctx);

    ECDSA_SIG *sig = ECDSA_do_sign_ex(hash, SHA256_DIGEST_LENGTH, k, r, prv);

    unsigned char sig_buffer[SIG_SIZE];
    unsigned char *sig_ptr = sig_buffer;
    int sig_buffer_len = i2d_ECDSA_SIG(sig, &sig_ptr);
    base64_encode(sig_buffer, sig_buffer_len, signature, signature_len);

    ECDSA_SIG_free(sig);
    EC_KEY_free(prv);
    BN_free(k);
    BN_free(r);
    BN_CTX_free(ctx);
    return 0;
}

int verify_signature(const char *public_key, const char *message, const char *signature) {
    EC_KEY *pub = load_public_key(public_key);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)message, strlen(message), hash);

    unsigned char sig_buffer[SIG_SIZE];
    size_t sig_buffer_len = base64_decode(signature, sig_buffer, sizeof(sig_buffer));

    const unsigned char *sig_ptr = sig_buffer;
    ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &sig_ptr, sig_buffer_len);

    if (!sig) {
        fprintf(stderr, "Error deserializing signature: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    int result = ECDSA_do_verify(hash, SHA256_DIGEST_LENGTH, sig, pub);
    ECDSA_SIG_free(sig);
    EC_KEY_free(pub);
    return result;
}