#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include "memfs.h"

// 生成随机密钥和 IV
void generate_random_key(unsigned char *key, unsigned char *iv);

// 加密函数
int encrypt_data(const unsigned char *plaintext, int plaintext_len,
                 unsigned char *key, unsigned char *iv,
                 unsigned char **ciphertext);

// 解密函数
int decrypt_data(const unsigned char *ciphertext, int ciphertext_len,
                 unsigned char *key, unsigned char *iv,
                 unsigned char **plaintext);

#endif // ENCRYPTION_H

