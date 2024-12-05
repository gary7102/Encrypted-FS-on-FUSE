// This is generate_random_key.h

#ifndef GENERATE_RANDOM_KEY_H
#define GENERATE_RANDOM_KEY_H

// 定義 AES-256 密鑰和 IV 的大小
#define AES_KEY_SIZE 32       // 256 bits
#define AES_BLOCK_SIZE 16     // 128 bits

// 函數聲明
void generate_random_key(unsigned char *key, unsigned char *iv);

#endif 

