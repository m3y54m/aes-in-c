#include <stdio.h>
#include <string.h>
#include "../include/aes.h"

int main(void)
{
  const uint8_t key[AES_BLOCK_SIZE] = {'k', 'k', 'k', 'k', 'e', 'e', 'e', 'e', 'y', 'y', 'y', 'y', '.', '.', '.', '.'};
  const uint8_t plaintext[AES_BLOCK_SIZE] = {'a', 'b', 'c', 'd', 'e', 'f', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0'};
  uint8_t ciphertext[AES_BLOCK_SIZE];
  uint8_t decrypted[AES_BLOCK_SIZE];

  printf("AES demo: encrypting one block and decrypting it back\n");

  printf("Key:        ");
  for (size_t i = 0; i < AES_BLOCK_SIZE; i++)
    printf("%02x ", key[i]);
  printf("\n");

  printf("Plaintext:  ");
  for (size_t i = 0; i < AES_BLOCK_SIZE; i++)
    printf("%02x ", plaintext[i]);
  printf("\n");

  if (aes_encrypt(plaintext, ciphertext, key, AES_KEY_128) != AES_SUCCESS)
  {
    fprintf(stderr, "aes_encrypt failed\n");
    return 2;
  }

  printf("Ciphertext: ");
  for (size_t i = 0; i < AES_BLOCK_SIZE; i++)
    printf("%02x ", ciphertext[i]);
  printf("\n");

  if (aes_decrypt(ciphertext, decrypted, key, AES_KEY_128) != AES_SUCCESS)
  {
    fprintf(stderr, "aes_decrypt failed\n");
    return 3;
  }

  printf("Decrypted:  ");
  for (size_t i = 0; i < AES_BLOCK_SIZE; i++)
    printf("%02x ", decrypted[i]);
  printf("\n");

  if (memcmp(plaintext, decrypted, AES_BLOCK_SIZE) != 0)
  {
    fprintf(stderr, "roundtrip mismatch\n");
    return 4;
  }

  printf("Roundtrip success\n");
  return 0;
}
