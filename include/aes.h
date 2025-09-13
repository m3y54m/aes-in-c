#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

#define AES_BLOCK_SIZE 16
#define AES_MAX_EXPANDED_KEY 240

typedef enum aes_error
{
    AES_SUCCESS = 0,
    AES_ERROR_UNKNOWN_KEYSIZE,
    AES_ERROR_MEMORY_ALLOCATION_FAILED,
} aes_error_t;

/* Supported cipher key sizes (in bytes). */
typedef enum aes_key_size
{
    AES_KEY_128 = 16,
    AES_KEY_192 = 24,
    AES_KEY_256 = 32
} aes_key_size_t;

/* Public API */
void expand_key(uint8_t *expanded_key, const uint8_t *key, aes_key_size_t size, size_t expanded_key_size);

aes_error_t aes_encrypt(const uint8_t *input, uint8_t *output, const uint8_t *key, aes_key_size_t size);

aes_error_t aes_decrypt(const uint8_t *input, uint8_t *output, const uint8_t *key, aes_key_size_t size);

#endif /* AES_H */
