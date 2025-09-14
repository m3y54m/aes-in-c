/**
 * @file aes.c
 * @brief An implementation of the AES (Rijndael) algorithm.
 *
 * @details This file contains the core implementation of the AES encryption
 * and decryption routines. It is designed to be self-contained and easy to
 * integrate. The state is handled in a column-major format consistent with
 * the FIPS-197 specification.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include "../include/aes.h"

// Internal constants for the AES implementation.
#define BITS_PER_BYTE 8
#define WORD_SIZE 4

// Number of rounds for each key size.
#define AES_ROUNDS_128 10
#define AES_ROUNDS_192 12
#define AES_ROUNDS_256 14

// Galois Field (GF(2^8)) constants for the MixColumns step.
#define GF_REDUCING_POLYNOMIAL 0x1B // Irreducible polynomial for AES: x^8 + x^4 + x^3 + x + 1
#define GF_MSB_MASK 0x80

/* --------------------------------------------------------------------------
 * S-Box and Inverse S-Box Lookup Tables
 * -------------------------------------------------------------------------- */

//! The AES Substitution Box (S-Box)
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

//! The AES Inverse Substitution Box (InvS-Box)
static const uint8_t rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

//! The Round Constant (Rcon) table used in the key schedule.
static const uint8_t rcon[] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a,
    0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39};

/**
 * @brief Securely erases a region of memory.
 * @param[in,out] ptr A pointer to the memory to be zeroed.
 * @param[in] n The number of bytes to zero.
 */
static void secure_zero_memory(void *ptr, size_t n)
{
  if (!ptr || n == 0)
    return;
  volatile uint8_t *p = (volatile uint8_t *)ptr;
  while (n--)
    *p++ = 0;
}

/**
 * @brief Performs a cyclic left shift on a 4-byte word.
 * @param[in,out] word A pointer to a 4-byte array to be rotated.
 */
static void word_rotate_left(uint8_t *word)
{
  uint8_t temp = word[0];
  word[0] = word[1];
  word[1] = word[2];
  word[2] = word[3];
  word[3] = temp;
}

/**
 * @brief The core transformation for the key expansion schedule.
 * @param[in,out] word The word to be transformed.
 * @param[in] iteration The current Rcon iteration.
 */
static void key_schedule_core(uint8_t *word, uint8_t iteration)
{
  word_rotate_left(word);
  for (uint8_t i = 0; i < WORD_SIZE; ++i)
    word[i] = sbox[word[i]];
  word[0] ^= rcon[iteration];
}

void aes_expand_key(uint8_t *expanded_key, const uint8_t *key, aes_key_size_t key_size, size_t expanded_key_size)
{
  size_t current_size = (size_t)key_size;
  uint8_t rcon_iteration = 1;
  uint8_t temp_word[WORD_SIZE];

  for (size_t i = 0; i < current_size; i++)
    expanded_key[i] = key[i];

  while (current_size < expanded_key_size)
  {
    for (size_t i = 0; i < WORD_SIZE; i++)
      temp_word[i] = expanded_key[current_size - WORD_SIZE + i];

    if (current_size % (size_t)key_size == 0)
    {
      key_schedule_core(temp_word, rcon_iteration++);
    }

    if (key_size == AES_KEY_SIZE_256 && (current_size % (size_t)key_size) == AES_BLOCK_SIZE)
    {
      for (size_t i = 0; i < WORD_SIZE; i++)
        temp_word[i] = sbox[temp_word[i]];
    }

    for (size_t i = 0; i < WORD_SIZE; i++)
    {
      expanded_key[current_size] = expanded_key[current_size - (size_t)key_size] ^ temp_word[i];
      current_size++;
    }
  }
}

/** @brief Applies the SubBytes transformation to the state. */
static void sub_bytes(aes_state_t *state)
{
  for (int r = 0; r < AES_STATE_DIM; ++r)
    for (int c = 0; c < AES_STATE_DIM; ++c)
      (*state)[r][c] = sbox[(*state)[r][c]];
}

/** @brief Applies the Inverse SubBytes transformation to the state. */
static void inv_sub_bytes(aes_state_t *state)
{
  for (int r = 0; r < AES_STATE_DIM; ++r)
    for (int c = 0; c < AES_STATE_DIM; ++c)
      (*state)[r][c] = rsbox[(*state)[r][c]];
}

/** @brief Applies the ShiftRows transformation to the state. */
static void shift_rows(aes_state_t *state)
{
  uint8_t temp;
  // Row 1: 1-byte left shift
  temp = (*state)[1][0];
  (*state)[1][0] = (*state)[1][1];
  (*state)[1][1] = (*state)[1][2];
  (*state)[1][2] = (*state)[1][3];
  (*state)[1][3] = temp;

  // Row 2: 2-byte left shift
  temp = (*state)[2][0];
  (*state)[2][0] = (*state)[2][2];
  (*state)[2][2] = temp;
  temp = (*state)[2][1];
  (*state)[2][1] = (*state)[2][3];
  (*state)[2][3] = temp;

  // Row 3: 3-byte left shift
  temp = (*state)[3][0];
  (*state)[3][0] = (*state)[3][3];
  (*state)[3][3] = (*state)[3][2];
  (*state)[3][2] = (*state)[3][1];
  (*state)[3][1] = temp;
}

/** @brief Applies the Inverse ShiftRows transformation to the state. */
static void inv_shift_rows(aes_state_t *state)
{
  uint8_t temp;
  // Row 1: 1-byte right shift
  temp = (*state)[1][3];
  (*state)[1][3] = (*state)[1][2];
  (*state)[1][2] = (*state)[1][1];
  (*state)[1][1] = (*state)[1][0];
  (*state)[1][0] = temp;

  // Row 2: 2-byte right shift
  temp = (*state)[2][0];
  (*state)[2][0] = (*state)[2][2];
  (*state)[2][2] = temp;
  temp = (*state)[2][1];
  (*state)[2][1] = (*state)[2][3];
  (*state)[2][3] = temp;

  // Row 3: 3-byte right shift
  temp = (*state)[3][3];
  (*state)[3][3] = (*state)[3][0];
  (*state)[3][0] = (*state)[3][1];
  (*state)[3][1] = (*state)[3][2];
  (*state)[3][2] = temp;
}

/**
 * @brief Performs multiplication in the Galois Field GF(2^8).
 * @param a The first operand.
 * @param b The second operand.
 * @return The result of (a * b) in GF(2^8).
 */
static uint8_t galois_mul(uint8_t a, uint8_t b)
{
  uint8_t p = 0;
  for (int i = 0; i < BITS_PER_BYTE; i++)
  {
    if (b & 1)
      p ^= a;
    uint8_t hi_bit_set = a & GF_MSB_MASK;
    a <<= 1;
    if (hi_bit_set)
      a ^= GF_REDUCING_POLYNOMIAL;
    b >>= 1;
  }
  return p;
}

/** @brief Applies the MixColumns transformation to the state. */
static void mix_columns(aes_state_t *state)
{
  uint8_t t[AES_STATE_DIM];
  for (int c = 0; c < AES_STATE_DIM; ++c)
  {
    for (int r = 0; r < AES_STATE_DIM; ++r)
      t[r] = (*state)[r][c];
    (*state)[0][c] = galois_mul(t[0], 2) ^ galois_mul(t[1], 3) ^ t[2] ^ t[3];
    (*state)[1][c] = t[0] ^ galois_mul(t[1], 2) ^ galois_mul(t[2], 3) ^ t[3];
    (*state)[2][c] = t[0] ^ t[1] ^ galois_mul(t[2], 2) ^ galois_mul(t[3], 3);
    (*state)[3][c] = galois_mul(t[0], 3) ^ t[1] ^ t[2] ^ galois_mul(t[3], 2);
  }
}

/** @brief Applies the Inverse MixColumns transformation to the state. */
static void inv_mix_columns(aes_state_t *state)
{
  uint8_t t[AES_STATE_DIM];
  for (int c = 0; c < AES_STATE_DIM; ++c)
  {
    for (int r = 0; r < AES_STATE_DIM; ++r)
      t[r] = (*state)[r][c];
    (*state)[0][c] = galois_mul(t[0], 14) ^ galois_mul(t[1], 11) ^ galois_mul(t[2], 13) ^ galois_mul(t[3], 9);
    (*state)[1][c] = galois_mul(t[0], 9) ^ galois_mul(t[1], 14) ^ galois_mul(t[2], 11) ^ galois_mul(t[3], 13);
    (*state)[2][c] = galois_mul(t[0], 13) ^ galois_mul(t[1], 9) ^ galois_mul(t[2], 14) ^ galois_mul(t[3], 11);
    (*state)[3][c] = galois_mul(t[0], 11) ^ galois_mul(t[1], 13) ^ galois_mul(t[2], 9) ^ galois_mul(t[3], 14);
  }
}

/**
 * @brief XORs the round key with the state.
 * @param[in,out] state The current state matrix.
 * @param[in] round_key The round key to be added.
 */
static void add_round_key(aes_state_t *state, const uint8_t *round_key)
{
  for (int c = 0; c < AES_STATE_DIM; ++c)
    for (int r = 0; r < AES_STATE_DIM; ++r)
      (*state)[r][c] ^= round_key[c * AES_STATE_DIM + r];
}

/**
 * @brief The main AES encryption cipher loop.
 * @param[in,out] state The 16-byte state to be encrypted.
 * @param[in] expanded_key The pre-computed key schedule.
 * @param[in] num_rounds The number of rounds for the given key size.
 */
static void cipher_encrypt_block(aes_state_t *state, const uint8_t *expanded_key, uint16_t num_rounds)
{
  add_round_key(state, expanded_key);
  for (uint16_t round = 1; round < num_rounds; round++)
  {
    sub_bytes(state);
    shift_rows(state);
    mix_columns(state);
    add_round_key(state, expanded_key + (AES_BLOCK_SIZE * round));
  }
  sub_bytes(state);
  shift_rows(state);
  add_round_key(state, expanded_key + (AES_BLOCK_SIZE * num_rounds));
}

/**
 * @brief The main AES decryption cipher loop.
 * @param[in,out] state The 16-byte state to be decrypted.
 * @param[in] expanded_key The pre-computed key schedule.
 * @param[in] num_rounds The number of rounds for the given key size.
 */
static void cipher_decrypt_block(aes_state_t *state, const uint8_t *expanded_key, uint16_t num_rounds)
{
  add_round_key(state, expanded_key + (AES_BLOCK_SIZE * num_rounds));
  for (uint16_t round = num_rounds; round > 1; round--)
  {
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, expanded_key + (AES_BLOCK_SIZE * (round - 1)));
    inv_mix_columns(state);
  }
  inv_shift_rows(state);
  inv_sub_bytes(state);
  add_round_key(state, expanded_key);
}

aes_error_t aes_encrypt(const uint8_t *plaintext,
                        uint8_t *ciphertext,
                        const uint8_t *key,
                        aes_key_size_t key_size)
{
  if (!plaintext || !ciphertext || !key)
    return AES_ERROR_UNSUPPORTED_KEY_SIZE;

  uint16_t num_rounds;
  switch (key_size)
  {
  case AES_KEY_SIZE_128:
    num_rounds = AES_ROUNDS_128;
    break;
  case AES_KEY_SIZE_192:
    num_rounds = AES_ROUNDS_192;
    break;
  case AES_KEY_SIZE_256:
    num_rounds = AES_ROUNDS_256;
    break;
  default:
    return AES_ERROR_UNSUPPORTED_KEY_SIZE;
  }

  size_t expanded_key_size = (size_t)AES_BLOCK_SIZE * (num_rounds + 1);
  uint8_t *expanded_key = (uint8_t *)malloc(expanded_key_size);
  if (!expanded_key)
    return AES_ERROR_MEMORY_ALLOCATION_FAILED;

  aes_expand_key(expanded_key, key, key_size, expanded_key_size);

  aes_state_t state;
  for (int r = 0; r < AES_STATE_DIM; ++r)
    for (int c = 0; c < AES_STATE_DIM; ++c)
      state[r][c] = plaintext[r + AES_STATE_DIM * c];

  cipher_encrypt_block(&state, expanded_key, num_rounds);

  for (int r = 0; r < AES_STATE_DIM; ++r)
    for (int c = 0; c < AES_STATE_DIM; ++c)
      ciphertext[r + AES_STATE_DIM * c] = state[r][c];

  secure_zero_memory(expanded_key, expanded_key_size);
  free(expanded_key);
  return AES_SUCCESS;
}

aes_error_t aes_decrypt(const uint8_t *ciphertext,
                        uint8_t *plaintext,
                        const uint8_t *key,
                        aes_key_size_t key_size)
{
  if (!ciphertext || !plaintext || !key)
    return AES_ERROR_UNSUPPORTED_KEY_SIZE;

  uint16_t num_rounds;
  switch (key_size)
  {
  case AES_KEY_SIZE_128:
    num_rounds = AES_ROUNDS_128;
    break;
  case AES_KEY_SIZE_192:
    num_rounds = AES_ROUNDS_192;
    break;
  case AES_KEY_SIZE_256:
    num_rounds = AES_ROUNDS_256;
    break;
  default:
    return AES_ERROR_UNSUPPORTED_KEY_SIZE;
  }

  size_t expanded_key_size = (size_t)AES_BLOCK_SIZE * (num_rounds + 1);
  uint8_t *expanded_key = (uint8_t *)malloc(expanded_key_size);
  if (!expanded_key)
    return AES_ERROR_MEMORY_ALLOCATION_FAILED;

  aes_expand_key(expanded_key, key, key_size, expanded_key_size);

  aes_state_t state;
  for (int r = 0; r < AES_STATE_DIM; ++r)
    for (int c = 0; c < AES_STATE_DIM; ++c)
      state[r][c] = ciphertext[r + AES_STATE_DIM * c];

  cipher_decrypt_block(&state, expanded_key, num_rounds);

  for (int r = 0; r < AES_STATE_DIM; ++r)
    for (int c = 0; c < AES_STATE_DIM; ++c)
      plaintext[r + AES_STATE_DIM * c] = state[r][c];

  secure_zero_memory(expanded_key, expanded_key_size);
  free(expanded_key);
  return AES_SUCCESS;
}

const char *aes_error_to_string(aes_error_t error_code)
{
  switch (error_code)
  {
  case AES_SUCCESS:
    return "Success";
  case AES_ERROR_UNSUPPORTED_KEY_SIZE:
    return "Unsupported key size";
  case AES_ERROR_MEMORY_ALLOCATION_FAILED:
    return "Memory allocation failed";
  default:
    return "An unknown error occurred";
  }
}