// this is generate_random_key.c

#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include "generate_random_key.h"  // 包含函數聲明

// 定義 AES-256 密鑰和 IV 的大小
#define AES_KEY_SIZE 32       // 256 bits
#define AES_BLOCK_SIZE 16     // 128 bits

// 生成隨機密鑰和 IV 的函數實現
void generate_random_key(unsigned char *key, unsigned char *iv) {
    if (!RAND_bytes(key, AES_KEY_SIZE)) {
        perror("Error generating random AES key");
        exit(EXIT_FAILURE);
    }
    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        perror("Error generating random AES IV");
        exit(EXIT_FAILURE);
    }
}

