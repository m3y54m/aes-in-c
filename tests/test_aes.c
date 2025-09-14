/**
 * @file test_aes.c
 * @brief Unit tests for the AES implementation.
 *
 * @details This file contains a set of tests to verify the correctness of the
 * AES encryption and decryption functions against known answer test (KAT)
 * vectors from the FIPS-197 standard.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../include/aes.h"

/* ============================================================================
 * Test Utilities
 * ========================================================================= */

/**
 * @brief Prints a byte array in hexadecimal format.
 * @param[in] label A descriptive label to print before the hex string.
 * @param[in] data A pointer to the byte array.
 * @param[in] len The number of bytes to print.
 */
static void print_hex(const char *label, const uint8_t *data, size_t len)
{
  printf("%-12s", label);
  for (size_t i = 0; i < len; i++)
  {
    printf("%02x ", data[i]);
  }
  printf("\n");
}

/**
 * @brief Runs a single AES test case.
 * @details This function encrypts a plaintext, verifies it against an expected
 * ciphertext, then decrypts the result and verifies it against the
 * original plaintext.
 * @param[in] test_name A descriptive name for the test case.
 * @param[in] key A pointer to the AES key.
 * @param[in] key_size The size of the key.
 * @param[in] plaintext The plaintext to be encrypted.
 * @param[in] expected_ciphertext The known-correct ciphertext for verification.
 * @return 0 on success, 1 on failure.
 */
static int run_fips_test_case(const char *test_name, const uint8_t *key, aes_key_size_t key_size, const uint8_t *plaintext, const uint8_t *expected_ciphertext)
{
  uint8_t ciphertext[AES_BLOCK_SIZE];
  uint8_t decrypted_plaintext[AES_BLOCK_SIZE];

  printf("\n--- Running Test Case: %s ---\n", test_name);
  print_hex("Key:", key, key_size);
  print_hex("Plaintext:", plaintext, AES_BLOCK_SIZE);

  aes_error_t result = aes_encrypt(plaintext, ciphertext, key, key_size);
  if (result != AES_SUCCESS)
  {
    fprintf(stderr, "FAIL: aes_encrypt failed with error: %s\n", aes_error_to_string(result));
    return 1;
  }
  print_hex("Ciphertext:", ciphertext, AES_BLOCK_SIZE);

  if (memcmp(ciphertext, expected_ciphertext, AES_BLOCK_SIZE) != 0)
  {
    fprintf(stderr, "FAIL: Ciphertext does not match the expected value.\n");
    print_hex("Expected:", expected_ciphertext, AES_BLOCK_SIZE);
    print_hex("Actual:", ciphertext, AES_BLOCK_SIZE);
    return 1;
  }

  result = aes_decrypt(ciphertext, decrypted_plaintext, key, key_size);
  if (result != AES_SUCCESS)
  {
    fprintf(stderr, "FAIL: aes_decrypt failed with error: %s\n", aes_error_to_string(result));
    return 1;
  }
  print_hex("Decrypted:", decrypted_plaintext, AES_BLOCK_SIZE);

  if (memcmp(plaintext, decrypted_plaintext, AES_BLOCK_SIZE) != 0)
  {
    fprintf(stderr, "FAIL: Decrypted text does not match the original plaintext.\n");
    return 1;
  }

  printf("PASS: Test passed!\n");
  return 0;
}

/* ============================================================================
 * Main Test Function
 * ========================================================================= */

/**
 * @brief The main entry point for the AES test suite.
 * @return 0 if all tests pass, 1 otherwise.
 */
int main(void)
{
  int failed_tests = 0;

  // Test Case 1: AES-128 from FIPS-197 Appendix C.1
  const uint8_t key128[] = {
      0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
      0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
  const uint8_t plaintext128[] = {
      0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
      0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
  const uint8_t ciphertext128[] = {
      0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
      0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32};
  failed_tests += run_fips_test_case("AES-128 FIPS-197 C.1", key128, AES_KEY_SIZE_128, plaintext128, ciphertext128);

  // Test Case 2: AES-192 from FIPS-197 Appendix C.2
  const uint8_t key192[] = {
      0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
      0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
      0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};
  const uint8_t plaintext192[] = {
      0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
      0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
  const uint8_t ciphertext192[] = {
      0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f,
      0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc};
  failed_tests += run_fips_test_case("AES-192 FIPS-197 C.2", key192, AES_KEY_SIZE_192, plaintext192, ciphertext192);

  // Test Case 3: AES-256 from FIPS-197 Appendix C.3
  const uint8_t key256[] = {
      0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
      0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
      0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
  const uint8_t plaintext256[] = {
      0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
      0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
  const uint8_t ciphertext256[] = {
      0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
      0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8};
  failed_tests += run_fips_test_case("AES-256 FIPS-197 C.3", key256, AES_KEY_SIZE_256, plaintext256, ciphertext256);

  if (failed_tests > 0)
  {
    fprintf(stderr, "\nSUMMARY: %d test(s) failed.\n", failed_tests);
    return 1;
  }

  printf("\nSUMMARY: All tests passed successfully!\n");
  return 0;
}