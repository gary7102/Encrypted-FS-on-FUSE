#include "encryption.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>

// 生成随机密钥和 IV
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

// 加密函数
int encrypt_data(const unsigned char *plaintext, int plaintext_len,
                 unsigned char *key, unsigned char *iv,
                 unsigned char **ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    *ciphertext = malloc(plaintext_len + AES_BLOCK_SIZE);
    if (*ciphertext == NULL) {
        return -1;
    }

    /* 创建和初始化上下文 */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        free(*ciphertext);
        return -1;
    }

    /* 初始化加密操作 */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        free(*ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* 加密数据 */
    if (1 != EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len)) {
        free(*ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    /* 结束加密 */
    if (1 != EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len)) {
        free(*ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    /* 清理 */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// 解密函数
int decrypt_data(const unsigned char *ciphertext, int ciphertext_len,
                 unsigned char *key, unsigned char *iv,
                 unsigned char **plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    *plaintext = malloc(ciphertext_len);
    if (*plaintext == NULL) {
        return -1;
    }

    /* 创建和初始化上下文 */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        free(*plaintext);
        return -1;
    }

    /* 初始化解密操作 */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        free(*plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* 解密数据 */
    if (1 != EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len)) {
        free(*plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    /* 结束解密 */
    if (1 != EVP_DecryptFinal_ex(ctx, *plaintext + len, &len)) {
        free(*plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    /* 清理 */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

