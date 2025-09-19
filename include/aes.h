/**
 * @file aes.h
 * @brief Public API for a clean and simple AES implementation.
 *
 * @details This header defines the public interface for AES (Advanced
 * Encryption Standard) encryption and decryption. It supports key sizes of
 * 128, 192, and 256 bits and operates on 16-byte (128-bit) blocks. The
 * implementation is designed for clarity and correctness.
 */

#ifndef AES_H
#define AES_H

#include <stddef.h>
#include <stdint.h>

/* ============================================================================
 * Public Compile-Time Constants
 * ========================================================================= */

/** @brief The block size for AES, which is always 128 bits (16 bytes). */
#define AES_BLOCK_SIZE 16

/** @brief The dimension of the square AES state matrix (4x4). */
#define AES_STATE_DIM 4

/**
 * @brief Maximum size for the expanded key schedule (for AES-256).
 * @details This is calculated as AES_BLOCK_SIZE * (max_rounds + 1),
 * which is 16 * (14 + 1) = 240 bytes.
 */
#define AES_MAX_EXPANDED_KEY_SIZE 240

/* ============================================================================
 * Public Enums and Typedefs
 * ========================================================================= */

/** @brief A type definition for the 4x4 byte AES state matrix. */
typedef uint8_t aes_state_t[AES_STATE_DIM][AES_STATE_DIM];

/**
 * @brief Enumeration of possible error codes returned by the AES functions.
 */
typedef enum
{
    AES_SUCCESS = 0,                    /**< The operation completed successfully. */
    AES_ERROR_UNSUPPORTED_KEY_SIZE,     /**< The provided key size is not supported. */
    AES_ERROR_MEMORY_ALLOCATION_FAILED, /**< A memory allocation call failed. */
} aes_error_t;

/**
 * @brief Enumeration of supported AES key sizes in bytes.
 */
typedef enum
{
    AES_KEY_SIZE_128 = 16, /**< For 128-bit keys (16 bytes). */
    AES_KEY_SIZE_192 = 24, /**< For 192-bit keys (24 bytes). */
    AES_KEY_SIZE_256 = 32  /**< For 256-bit keys (32 bytes). */
} aes_key_size_t;

/* ============================================================================
 * Public API
 * ========================================================================= */

/**
 * @brief Expands the given AES key into a round key schedule.
 *
 * @param[out] expanded_key A pointer to the buffer where the expanded key will be stored.
 * The size must be sufficient for the chosen key size.
 * @param[in]  key A pointer to the original AES key.
 * @param[in]  key_size The size of the key (use AES_KEY_SIZE_128, AES_KEY_SIZE_192, or AES_KEY_SIZE_256).
 * @param[in]  expanded_key_size The total size of the expanded_key buffer.
 */
void aes_expand_key(uint8_t* expanded_key, const uint8_t* key, aes_key_size_t key_size, size_t expanded_key_size);

/**
 * @brief Encrypts a single 16-byte block of data using AES.
 *
 * @param[in]  plaintext A pointer to the 16-byte plaintext block to be encrypted.
 * @param[out] ciphertext A pointer to the 16-byte buffer where the resulting ciphertext will be stored.
 * @param[in]  key A pointer to the AES key.
 * @param[in]  key_size The size of the key (128, 192, or 256 bits).
 * @return AES_SUCCESS on success, or an appropriate aes_error_t on failure.
 */
aes_error_t aes_encrypt(const uint8_t* plaintext, uint8_t* ciphertext, const uint8_t* key, aes_key_size_t key_size);

/**
 * @brief Decrypts a single 16-byte block of data using AES.
 *
 * @param[in]  ciphertext A pointer to the 16-byte ciphertext block to be decrypted.
 * @param[out] plaintext A pointer to the 16-byte buffer where the resulting plaintext will be stored.
 * @param[in]  key A pointer to the AES key.
 * @param[in]  key_size The size of the key (128, 192, or 256 bits).
 * @return AES_SUCCESS on success, or an appropriate aes_error_t on failure.
 */
aes_error_t aes_decrypt(const uint8_t* ciphertext, uint8_t* plaintext, const uint8_t* key, aes_key_size_t key_size);

/**
 * @brief Converts an AES error code to a human-readable string.
 *
 * @param[in] error_code The error code to convert.
 * @return A constant string describing the error.
 */
const char* aes_error_to_string(aes_error_t error_code);

#endif // AES_H
