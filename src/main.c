/* Basic implementation of AES in C
 *
 * NOTE: This code is provided for learning and demonstration purposes only.
 * It is not intended for production use or as a secure cryptographic library.
 */

#include <stdio.h>  // for printf
#include <stdlib.h> // for malloc, free
#include <stdint.h> // for uint8_t
#include <stddef.h> // for size_t

/* Error codes returned by public AES functions. */
typedef enum aes_error
{
    AES_SUCCESS = 0,
    AES_ERROR_UNKNOWN_KEYSIZE,
    AES_ERROR_MEMORY_ALLOCATION_FAILED,
} aes_error_t;

// Implementation: S-Box

static const uint8_t sbox[256] = {
    // 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,  // 0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,  // 1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,  // 2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,  // 3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,  // 4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,  // 5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,  // 6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,  // 7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,  // 8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,  // 9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,  // A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,  // B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,  // C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,  // D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,  // E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}; // F

static const uint8_t rsbox[256] =
    {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

static uint8_t sbox_get(uint8_t num);
static uint8_t sbox_inverse_get(uint8_t num);

// Implementation: Rotate
static void word_rotate_left(uint8_t *word);

// Implementation: Rcon
static const uint8_t rcon[255] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab,
    0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
    0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25,
    0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01,
    0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
    0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa,
    0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
    0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02,
    0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f,
    0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
    0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33,
    0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb};

static uint8_t rcon_get(uint8_t num);

// Implementation: Key Schedule Core
static void key_schedule_core(uint8_t *word, uint8_t iteration);

// Implementation: Key Expansion

/* Supported cipher key sizes (in bytes). */
typedef enum aes_key_size
{
    AES_KEY_128 = 16,
    AES_KEY_192 = 24,
    AES_KEY_256 = 32
} aes_key_size_t;

void expand_key(uint8_t *expanded_key, const uint8_t *key, aes_key_size_t size, size_t expanded_key_size);

/* Securely zero memory (simple portable fallback). Use platform APIs if available. */
static void secure_zero(void *p, size_t n)
{
    if (p == NULL || n == 0)
        return;
    volatile uint8_t *q = (volatile uint8_t *)p;
    while (n--)
        *q++ = 0;
}

// Implementation: AES Encryption

// Implementation: subBytes
static void sub_bytes(uint8_t *state);
// Implementation: shiftRows
static void shift_rows(uint8_t *state);
static void shift_row(uint8_t *state, uint8_t nbr);
// Implementation: addRoundKey
static void add_round_key(uint8_t *state, uint8_t *round_key);
// Implementation: mixColumns
static uint8_t galois_mul(uint8_t a, uint8_t b);
static void mix_columns(uint8_t *state);
static void mix_column(uint8_t *column);
// Implementation: AES round
static void round_encrypt(uint8_t *state, uint8_t *round_key);
// Implementation: the main AES body
static void create_round_key(uint8_t *expanded_key, uint8_t *round_key);
static void cipher_encrypt_block(uint8_t *state, uint8_t *expanded_key, uint16_t nbr_rounds);
// Implementation: AES encryption
aes_error_t aes_encrypt(const uint8_t *input, uint8_t *output, const uint8_t *key, aes_key_size_t size);
// AES Decryption
static void inv_sub_bytes(uint8_t *state);
static void inv_shift_rows(uint8_t *state);
static void inv_shift_row(uint8_t *state, uint8_t nbr);
static void inv_mix_columns(uint8_t *state);
static void inv_mix_column(uint8_t *column);
static void round_decrypt(uint8_t *state, uint8_t *round_key);
static void cipher_decrypt_block(uint8_t *state, uint8_t *expanded_key, uint16_t nbr_rounds);
aes_error_t aes_decrypt(const uint8_t *input, uint8_t *output, const uint8_t *key, aes_key_size_t size);

int main()
{
    // the expanded key_size
    size_t expanded_key_size = 176;

    // the expanded key (heap-allocated to avoid VLAs)
    uint8_t *expanded_key = (uint8_t *)malloc(expanded_key_size);
    if (expanded_key == NULL)
    {
        fprintf(stderr, "Failed to allocate expanded_key\n");
        return 1;
    }

    // the cipher key
    uint8_t key[16] = {'k', 'k', 'k', 'k', 'e', 'e', 'e', 'e', 'y', 'y', 'y', 'y', '.', '.', '.', '.'};

    // the cipher key size
    aes_key_size_t size = AES_KEY_128;

    // the plaintext
    uint8_t plaintext[16] = {'a', 'b', 'c', 'd', 'e', 'f', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0'};

    // the ciphertext
    uint8_t ciphertext[16];

    // the decrypted text
    uint8_t decryptedtext[16];

    printf("**************************************************\n");
    printf("*   Basic implementation of AES algorithm in C   *\n");
    printf("**************************************************\n");

    printf("\nCipher Key (HEX format):\n");

    for (uint8_t i = 0; i < 16; i++)
    {
        // Print characters in HEX format, 16 chars per line
        printf("%2.2x%c", key[i], ((i + 1) % 16) ? ' ' : '\n');
    }

    // Test the Key Expansion
    expand_key(expanded_key, key, size, expanded_key_size);

    printf("\nExpanded Key (HEX format):\n");

    for (size_t i = 0; i < expanded_key_size; i++)
    {
        printf("%2.2x%c", expanded_key[i], ((i + 1) % 16) ? ' ' : '\n');
    }

    printf("\nPlaintext (HEX format):\n");

    for (uint8_t i = 0; i < 16; i++)
    {
        printf("%2.2x%c", plaintext[i], ((i + 1) % 16) ? ' ' : '\n');
    }

    // AES Encryption
    aes_encrypt(plaintext, ciphertext, key, size);

    printf("\nCiphertext (HEX format):\n");

    for (uint8_t i = 0; i < 16; i++)
    {
        printf("%2.2x%c", ciphertext[i], ((i + 1) % 16) ? ' ' : '\n');
    }

    // AES Decryption
    aes_decrypt(ciphertext, decryptedtext, key, size);

    printf("\nDecrypted text (HEX format):\n");

    for (uint8_t i = 0; i < 16; i++)
    {
        printf("%2.2x%c", decryptedtext[i], ((i + 1) % 16) ? ' ' : '\n');
    }

    // securely wipe expanded key before exit
    secure_zero(expanded_key, expanded_key_size);
    free(expanded_key);
    expanded_key = NULL;

    return 0;
}

static uint8_t sbox_get(uint8_t num)
{
    return sbox[num];
}

static uint8_t sbox_inverse_get(uint8_t num)
{
    return rsbox[num];
}

/* Rijndael's key schedule rotate operation
 * rotate the word eight bits to the left
 *
 * rotate(1d2c3a4f) = 2c3a4f1d
 *
 * word is an uint8_t array of size 4 (32 bit)
 */
static void word_rotate_left(uint8_t *word)
{
    uint8_t tmp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = tmp;
}

static uint8_t rcon_get(uint8_t num)
{
    return rcon[num];
}

static void key_schedule_core(uint8_t *word, uint8_t iteration)
{
    uint8_t i;

    /* Rotate the 32-bit word 8 bits to the left, substitute through S-box,
       then XOR the first byte with the appropriate rcon value. */
    word_rotate_left(word);

    for (i = 0; i < 4; ++i)
        word[i] = sbox_get(word[i]);

    word[0] ^= rcon_get(iteration);
}

/* Rijndael's key expansion
 * expands an 128,192,256 key into an 176,208,240 bytes key
 *
 * expanded_key is a pointer to an uint8_t array of large enough size
 * key is a pointer to a non-expanded key
 */

void expand_key(uint8_t *expanded_key,
                const uint8_t *key,
                aes_key_size_t size,
                size_t expanded_key_size)
{
    // current expanded key_size, in bytes
    size_t current_size = 0;
    uint8_t rcon_iteration = 1;
    uint8_t t[4] = {0}; // temporary 4-byte variable

    // set the 16,24,32 bytes of the expanded key to the input key
    for (size_t i = 0; i < (size_t)size; i++)
        expanded_key[i] = key[i];
    current_size += (size_t)size;

    while (current_size < expanded_key_size)
    {
        // assign the previous 4 bytes to the temporary value t
        for (uint8_t i = 0; i < 4; i++)
        {
            t[i] = expanded_key[(current_size - 4) + i];
        }

        /* every 16,24,32 bytes we apply the core schedule to t
         * and increment rcon_iteration afterwards
         */
        if (current_size % size == 0)
        {
            key_schedule_core(t, rcon_iteration++);
        }

        // For 256-bit keys, we add an extra sbox to the calculation
        if (size == AES_KEY_256 && ((current_size % (size_t)size) == 16))
        {
            for (uint8_t i = 0; i < 4; i++)
                t[i] = sbox_get(t[i]);
        }

        /* We XOR t with the four-byte block 16,24,32 bytes before the new expanded key.
         * This becomes the next four bytes in the expanded key.
         */
        for (uint8_t i = 0; i < 4; i++)
        {
            expanded_key[current_size] = expanded_key[current_size - (size_t)size] ^ t[i];
            current_size++;
        }
    }
}

static void sub_bytes(uint8_t *state)
{
    /* substitute all the values from the state with the value in the SBox
     * using the state value as index for the SBox
     */
    for (uint8_t i = 0; i < 16; i++)
        state[i] = sbox_get(state[i]);
}

static void shift_rows(uint8_t *state)
{
    uint8_t i;
    // iterate over the 4 rows and call shiftRow() with that row
    for (i = 0; i < 4; i++)
        shift_row(state + i * 4, i);
}

static void shift_row(uint8_t *state, uint8_t nbr)
{
    uint8_t tmp;
    // each iteration shifts the row to the left by 1
    for (uint8_t i = 0; i < nbr; i++)
    {
        tmp = state[0];
        for (uint8_t j = 0; j < 3; j++)
            state[j] = state[j + 1];
        state[3] = tmp;
    }
}

static void add_round_key(uint8_t *state, uint8_t *round_key)
{
    for (uint8_t i = 0; i < 16; i++)
        state[i] = state[i] ^ round_key[i];
}

static uint8_t galois_mul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    uint8_t hi_bit_set;
    for (uint8_t counter = 0; counter < 8; counter++)
    {
        if ((b & 1) == 1)
            p ^= a;
        hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set == 0x80)
            a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

static void mix_columns(uint8_t *state)
{
    uint8_t column[4];

    // iterate over the 4 columns
    for (uint8_t i = 0; i < 4; i++)
    {
        // construct one column by iterating over the 4 rows
        for (uint8_t j = 0; j < 4; j++)
        {
            column[j] = state[(j * 4) + i];
        }

        // apply the mix_column on one column
        mix_column(column);

        // put the values back into the state
        for (uint8_t j = 0; j < 4; j++)
        {
            state[(j * 4) + i] = column[j];
        }
    }
}

static void mix_column(uint8_t *column)
{
    uint8_t cpy[4];
    for (uint8_t i = 0; i < 4; i++)
    {
        cpy[i] = column[i];
    }
    column[0] = galois_mul(cpy[0], 2) ^
                galois_mul(cpy[3], 1) ^
                galois_mul(cpy[2], 1) ^
                galois_mul(cpy[1], 3);

    column[1] = galois_mul(cpy[1], 2) ^
                galois_mul(cpy[0], 1) ^
                galois_mul(cpy[3], 1) ^
                galois_mul(cpy[2], 3);

    column[2] = galois_mul(cpy[2], 2) ^
                galois_mul(cpy[1], 1) ^
                galois_mul(cpy[0], 1) ^
                galois_mul(cpy[3], 3);

    column[3] = galois_mul(cpy[3], 2) ^
                galois_mul(cpy[2], 1) ^
                galois_mul(cpy[1], 1) ^
                galois_mul(cpy[0], 3);
}

static void round_encrypt(uint8_t *state, uint8_t *round_key)
{
    sub_bytes(state);
    shift_rows(state);
    mix_columns(state);
    add_round_key(state, round_key);
}

static void create_round_key(uint8_t *expanded_key, uint8_t *round_key)
{
    // iterate over the columns
    for (uint8_t i = 0; i < 4; i++)
    {
        // iterate over the rows
        for (uint8_t j = 0; j < 4; j++)
            round_key[(i + (j * 4))] = expanded_key[(i * 4) + j];
    }
}

static void cipher_encrypt_block(uint8_t *state, uint8_t *expanded_key, uint16_t nbr_rounds)
{
    uint8_t round_key[16];

    create_round_key(expanded_key, round_key);
    add_round_key(state, round_key);

    for (uint8_t i = 1; i < nbr_rounds; i++)
    {
        create_round_key(expanded_key + 16 * i, round_key);
        round_encrypt(state, round_key);
    }

    create_round_key(expanded_key + 16 * nbr_rounds, round_key);
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_key);
}

aes_error_t aes_encrypt(const uint8_t *input,
                        uint8_t *output,
                        const uint8_t *key,
                        aes_key_size_t size)
{
    // the expanded key_size
    size_t expanded_key_size;

    // the number of rounds
    uint16_t nbr_rounds;

    // the expanded key
    uint8_t *expanded_key;

    // the 128 bit block to encode
    uint8_t block[16];

    // set the number of rounds
    switch (size)
    {
    case AES_KEY_128:
        nbr_rounds = 10;
        break;
    case AES_KEY_192:
        nbr_rounds = 12;
        break;
    case AES_KEY_256:
        nbr_rounds = 14;
        break;
    default:
        return AES_ERROR_UNKNOWN_KEYSIZE;
    }

    expanded_key_size = (16 * (nbr_rounds + 1));

    expanded_key = (uint8_t *)malloc(expanded_key_size);

    if (expanded_key == NULL)
    {
        return AES_ERROR_MEMORY_ALLOCATION_FAILED;
    }

    /* Set the block values, for the block:
     * a0,0 a0,1 a0,2 a0,3
     * a1,0 a1,1 a1,2 a1,3
     * a2,0 a2,1 a2,2 a2,3
     * a3,0 a3,1 a3,2 a3,3
     * the mapping order is a0,0 a1,0 a2,0 a3,0 a0,1 a1,1 ... a2,3 a3,3
     */

    // iterate over the columns
    for (uint8_t i = 0; i < 4; i++)
    {
        // iterate over the rows
        for (uint8_t j = 0; j < 4; j++)
            block[(i + (j * 4))] = input[(i * 4) + j];
    }

    // expand the key into an 176, 208, 240 bytes key
    expand_key(expanded_key, key, size, expanded_key_size);

    // encrypt the block using the expanded_key
    cipher_encrypt_block(block, expanded_key, nbr_rounds);

    // unmap the block again into the output
    for (uint8_t i = 0; i < 4; i++)
    {
        // iterate over the rows
        for (uint8_t j = 0; j < 4; j++)
            output[(i * 4) + j] = block[(i + (j * 4))];
    }

    // de-allocate memory for expanded_key (securely)
    secure_zero(expanded_key, expanded_key_size);
    free(expanded_key);
    expanded_key = NULL;

    return AES_SUCCESS;
}

static void inv_sub_bytes(uint8_t *state)
{
    /* substitute all the values from the state with the value in the inverse S-box */
    for (uint8_t i = 0; i < 16; i++)
        state[i] = sbox_inverse_get(state[i]);
}

static void inv_shift_rows(uint8_t *state)
{
    uint8_t i;
    /* Iterate over the 4 rows and call inv_shift_row() on each. */
    for (i = 0; i < 4; i++)
        inv_shift_row(state + i * 4, i);
}

static void inv_shift_row(uint8_t *state, uint8_t nbr)
{
    uint8_t tmp;
    /* Each iteration shifts the row one byte to the right. */
    for (uint8_t i = 0; i < nbr; i++)
    {
        tmp = state[3];
        for (uint8_t j = 3; j > 0; j--)
            state[j] = state[j - 1];
        state[0] = tmp;
    }
}

static void inv_mix_columns(uint8_t *state)
{
    uint8_t column[4];

    /* Iterate over the 4 columns, extract, inverse-mix, and write back. */
    for (uint8_t i = 0; i < 4; i++)
    {
        for (uint8_t j = 0; j < 4; j++)
            column[j] = state[(j * 4) + i];

        inv_mix_column(column);

        for (uint8_t j = 0; j < 4; j++)
            state[(j * 4) + i] = column[j];
    }
}

static void inv_mix_column(uint8_t *column)
{
    uint8_t cpy[4];
    for (uint8_t i = 0; i < 4; i++)
        cpy[i] = column[i];

    column[0] = galois_mul(cpy[0], 14) ^
                galois_mul(cpy[3], 9) ^
                galois_mul(cpy[2], 13) ^
                galois_mul(cpy[1], 11);
    column[1] = galois_mul(cpy[1], 14) ^
                galois_mul(cpy[0], 9) ^
                galois_mul(cpy[3], 13) ^
                galois_mul(cpy[2], 11);
    column[2] = galois_mul(cpy[2], 14) ^
                galois_mul(cpy[1], 9) ^
                galois_mul(cpy[0], 13) ^
                galois_mul(cpy[3], 11);
    column[3] = galois_mul(cpy[3], 14) ^
                galois_mul(cpy[2], 9) ^
                galois_mul(cpy[1], 13) ^
                galois_mul(cpy[0], 11);
}

static void round_decrypt(uint8_t *state, uint8_t *round_key)
{
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, round_key);
    inv_mix_columns(state);
}

static void cipher_decrypt_block(uint8_t *state, uint8_t *expanded_key, uint16_t nbr_rounds)
{
    uint8_t round_key[16];

    create_round_key(expanded_key + 16 * nbr_rounds, round_key);
    add_round_key(state, round_key);

    for (uint16_t i = nbr_rounds - 1; i > 0; i--)
    {
        create_round_key(expanded_key + 16 * i, round_key);
        round_decrypt(state, round_key);
    }

    create_round_key(expanded_key, round_key);
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, round_key);
}

aes_error_t aes_decrypt(const uint8_t *input,
                        uint8_t *output,
                        const uint8_t *key,
                        aes_key_size_t size)
{
    // the expanded key_size
    size_t expanded_key_size;

    // the number of rounds
    uint16_t nbr_rounds;

    // the expanded key
    uint8_t *expanded_key;

    // the 128 bit block to decode
    uint8_t block[16];

    // set the number of rounds
    switch (size)
    {
    case AES_KEY_128:
        nbr_rounds = 10;
        break;
    case AES_KEY_192:
        nbr_rounds = 12;
        break;
    case AES_KEY_256:
        nbr_rounds = 14;
        break;
    default:
        return AES_ERROR_UNKNOWN_KEYSIZE;
    }

    expanded_key_size = (16 * (nbr_rounds + 1));

    expanded_key = (uint8_t *)malloc(expanded_key_size);

    if (expanded_key == NULL)
    {
        return AES_ERROR_MEMORY_ALLOCATION_FAILED;
    }

    /* Set the block values, for the block:
     * a0,0 a0,1 a0,2 a0,3
     * a1,0 a1,1 a1,2 a1,3
     * a2,0 a2,1 a2,2 a2,3
     * a3,0 a3,1 a3,2 a3,3
     * the mapping order is a0,0 a1,0 a2,0 a3,0 a0,1 a1,1 ... a2,3 a3,3
     */

    // iterate over the columns
    for (uint8_t i = 0; i < 4; i++)
    {
        // iterate over the rows
        for (uint8_t j = 0; j < 4; j++)
            block[(i + (j * 4))] = input[(i * 4) + j];
    }

    // expand the key into an 176, 208, 240 bytes key
    expand_key(expanded_key, key, size, expanded_key_size);

    // decrypt the block using the expanded_key
    cipher_decrypt_block(block, expanded_key, nbr_rounds);

    // unmap the block again into the output
    for (uint8_t i = 0; i < 4; i++)
    {
        // iterate over the rows
        for (uint8_t j = 0; j < 4; j++)
            output[(i * 4) + j] = block[(i + (j * 4))];
    }

    // de-allocate memory for expanded_key (securely)
    secure_zero(expanded_key, expanded_key_size);
    free(expanded_key);
    expanded_key = NULL;

    return AES_SUCCESS;
}
