/*
 *	!! This is old memfs.c  !!!
 *	I seperate this file to many .c/.h files instead
 *	Therefore, Makefile do not include this memfs.c file!
 * */


#define FUSE_USE_VERSION 31

#include <unistd.h>
#include <fuse3/fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <stdlib.h>


// 添加 OpenSSL 头文件
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>


// include header file
#include "generate_random_key.h"


// 定义 AES-256 密钥和 IV 大小
#define AES_KEY_SIZE 32 // 256 bits
#define AES_BLOCK_SIZE 16 // 128 bits

// 定义文件或目录的类型
typedef enum {
    NODE_FILE,
    NODE_DIR
} node_type;

// 定义文件节点结构
typedef struct memfs_node {
    char *name;
    node_type type;
    mode_t mode;
    uid_t uid;
    gid_t gid;
    time_t atime;
    time_t mtime;
    time_t ctime;
    size_t size;            // 加密后的数据大小
    size_t plaintext_size;  // 明文数据大小
    char *data;             // 存储加密后的数据
    unsigned char aes_key[AES_KEY_SIZE];  // 文件的 AES 密钥
    unsigned char aes_iv[AES_BLOCK_SIZE]; // 文件的 AES IV

    struct memfs_node *parent;
    struct memfs_node *children;
    struct memfs_node *next;
} memfs_node;

// 根目录节点
memfs_node *root;

// 初始化 OpenSSL 库（可选）
//void init_openssl() {
    /* 初始化 OpenSSL 算法库 */
//    ERR_load_crypto_strings();
//    OpenSSL_add_all_algorithms();
//    OPENSSL_config(NULL);
//}

// 清理 OpenSSL 库（可选）
//void cleanup_openssl() {
    /* 清理 OpenSSL 算法库 */
//    EVP_cleanup();
//    ERR_free_strings();
//}

// 生成随机密钥和 IV
/*
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
*/

// 辅助函数：创建新节点
memfs_node *create_node(const char *name, node_type type, mode_t mode, memfs_node *parent) {
    memfs_node *node = (memfs_node *)malloc(sizeof(memfs_node));
    node->name = strdup(name);
    node->type = type;
    node->mode = mode;
    node->uid = getuid();
    node->gid = getgid();
    node->atime = node->mtime = node->ctime = time(NULL);
    node->size = 0;
    node->plaintext_size = 0;
    node->data = NULL;
    node->parent = parent;
    node->children = NULL;
    node->next = NULL;

    if (type == NODE_FILE) {
        // 为新文件生成随机密钥和 IV
        generate_random_key(node->aes_key, node->aes_iv);

        printf("Generated AES Key for %s: ", name);
        for (int i = 0; i < AES_KEY_SIZE; i++) {
            printf("%02x", node->aes_key[i]);
        }
        printf("\n");

        printf("Generated AES IV for %s: ", name);
        for (int i = 0; i < AES_BLOCK_SIZE; i++) {
            printf("%02x", node->aes_iv[i]);
        }
        printf("\n");
    }

    return node;
}

// 查找节点的函数
memfs_node *find_node(const char *path) {
    if (strcmp(path, "/") == 0) {
        return root;
    }

    char *path_dup = strdup(path);
    char *token;
    char *saveptr;
    memfs_node *current = root;

    // split the path by "/"
    token = strtok_r(path_dup, "/", &saveptr);
    while (token != NULL) {
        memfs_node *temp = current->children;
        while (temp != NULL) {
            if (strcmp(temp->name, token) == 0) {
                break;
            }
            temp = temp->next;
        }
        if (temp == NULL) {
            free(path_dup);
            return NULL;
        }
        current = temp;
        token = strtok_r(NULL, "/", &saveptr);
    }

    free(path_dup);
    return current;
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

// 实现 getattr 回调函数
static int memfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    (void) fi;
    memset(stbuf, 0, sizeof(struct stat));

    memfs_node *node = find_node(path);
    if (node == NULL) {
        return -ENOENT;
    }

    stbuf->st_mode = node->mode;
    stbuf->st_uid = node->uid;
    stbuf->st_gid = node->gid;
    stbuf->st_atime = node->atime;
    stbuf->st_mtime = node->mtime;
    stbuf->st_ctime = node->ctime;

    if (node->type == NODE_DIR) {
        stbuf->st_mode |= S_IFDIR;
        stbuf->st_nlink = 2;
    } else {
        stbuf->st_mode |= S_IFREG;
        stbuf->st_nlink = 1;
        stbuf->st_size = node->plaintext_size; // 返回明文数据大小
    }

    return 0;
}

// 实现 readdir 回调函数
static int memfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi,
                         enum fuse_readdir_flags flags) {
    (void) offset;
    (void) fi;
    (void) flags;

    memfs_node *node = find_node(path);
    if (node == NULL || node->type != NODE_DIR) {
        return -ENOENT;
    }

    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);

    memfs_node *child = node->children;
    while (child != NULL) {
        filler(buf, child->name, NULL, 0, 0);
        child = child->next;
    }

    return 0;
}

// 实现 mkdir 回调函数
static int memfs_mkdir(const char *path, mode_t mode) {
    printf("mkdir called for path: %s\n", path);
    char *dup_path = strdup(path);
    char *dir_name = strrchr(dup_path, '/');
    memfs_node *parent;

    if (dir_name == dup_path) {
        parent = root;
        dir_name++;
    } else {
        *dir_name = '\0';
        parent = find_node(dup_path);
        dir_name++;
    }

    if (parent == NULL || parent->type != NODE_DIR) {
        free(dup_path);
        return -ENOENT;
    }

    memfs_node *temp = parent->children;
    while (temp != NULL) {
        if (strcmp(temp->name, dir_name) == 0) {
            free(dup_path);
            return -EEXIST;
        }
        temp = temp->next;
    }

    memfs_node *new_dir = create_node(dir_name, NODE_DIR, mode, parent);
    new_dir->next = parent->children;
    parent->children = new_dir;

    free(dup_path);
    return 0;
}


// 实现 create 回调函数
static int memfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    (void) fi;
    printf("create called for path: %s\n", path);
    char *dup_path = strdup(path);
    char *file_name = strrchr(dup_path, '/');
    memfs_node *parent;

    if (file_name == dup_path) {
        parent = root;
        file_name++;
    } else {
        *file_name = '\0';
        parent = find_node(dup_path);
        file_name++;
    }

    if (parent == NULL || parent->type != NODE_DIR) {
        free(dup_path);
        return -ENOENT;
    }

    memfs_node *temp = parent->children;
    while (temp != NULL) {
        if (strcmp(temp->name, file_name) == 0) {
            free(dup_path);
            return -EEXIST;
        }
        temp = temp->next;
    }

    memfs_node *new_file = create_node(file_name, NODE_FILE, mode, parent);

    new_file->next = parent->children;
    parent->children = new_file;

    free(dup_path);
    return 0;
}


// 实现 mknod 回调函数
static int memfs_mknod(const char *path, mode_t mode, dev_t rdev) {
    printf("mknod called for path: %s\n", path);

    if (S_ISREG(mode)) {
        // 如果是常规文件，调用 memfs_create
        return memfs_create(path, mode, NULL);
    } else if (S_ISDIR(mode)) {
        // 如果是目录，调用 memfs_mkdir
        return memfs_mkdir(path, mode);
    } else {
        // 其他类型（如设备文件），不支持
        printf("mknod: special file types not supported\n");
        return -EPERM;
    }
}



// 实现 open 回调函数
static int memfs_open(const char *path, struct fuse_file_info *fi) {
    printf("open called for path: %s\n", path);
    memfs_node *node = find_node(path);
    if (node == NULL) {
        printf("open: node not found\n");
        return -ENOENT;
    }
    if (node->type != NODE_FILE) {
        printf("open: not a file\n");
        return -EISDIR;
    }
    return 0;
}

/*
// using wrong key to read file, can't acces!!
int memfs_read(const char *path, char *buf, size_t size, off_t offset,
               struct fuse_file_info *fi) {
    memfs_node *node = find_node(path);
    unsigned char *decrypted_data = NULL;

    // 定義錯誤的 AES 金鑰（與正確金鑰不同）
    unsigned char wrong_key[AES_KEY_SIZE] = "wrongkey12345678901234567890abcd";

    // 使用錯誤的金鑰進行解密
    int decrypted_size = decrypt_data((unsigned char *)node->data, node->size,
                                      wrong_key, node->aes_iv, &decrypted_data);

    // 檢查解密是否成功
    if (decrypted_size < 0) {
        printf("Decryption failed with wrong key!\n");
        return -EIO;  // 返回錯誤，表示解密失敗
    }

    if (offset >= decrypted_size) {
        free(decrypted_data);
        return 0;
    }
    if (offset + size > decrypted_size) {
        size = decrypted_size - offset;
    }
    memcpy(buf, decrypted_data + offset, size);
    free(decrypted_data);
    return size;
}
*/



// 实现 read 回调函数（添加解密操作）
static int memfs_read(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi) {
    (void) fi;
    printf("read called for path: %s, size: %zu, offset: %ld\n", path, size, offset);
    
    
    memfs_node *node = find_node(path);
    if (node == NULL) {
        printf("read: node not found\n");
        return -ENOENT;
    }
    if (node->type != NODE_FILE) {
        printf("read: not a file\n");
        return -EISDIR;
    }

    if (node->data == NULL || node->size == 0) {
        return 0;
    }



    // 解密数据
    unsigned char *decrypted_data = NULL;
    int decrypted_size = decrypt_data((unsigned char *)node->data, node->size,
                                      node->aes_key, node->aes_iv, &decrypted_data);
    if (decrypted_size < 0) {
        printf("read: decryption failed\n");
        return -EIO;
    }

    if (offset >= decrypted_size) {
        free(decrypted_data);
        return 0;
    }
    if (offset + size > decrypted_size) {
        size = decrypted_size - offset;
    }
    memcpy(buf, decrypted_data + offset, size);

    free(decrypted_data);
    return size;
}



// 实现 write 回调函数（添加加密操作）
static int memfs_write(const char *path, const char *buf, size_t size, off_t offset,
                       struct fuse_file_info *fi) {
    printf("write called for path: %s, size: %zu, offset: %ld\n", path, size, offset);

    memfs_node *node = find_node(path);
    if (node == NULL) {
        return -ENOENT;
    }

    if (node->type != NODE_FILE) {
        return -EISDIR;
    }

    // 解密现有数据
    unsigned char *existing_data = NULL;
    int existing_size = 0;

    if (node->data != NULL && node->size > 0) {
        existing_size = decrypt_data((unsigned char *)node->data, node->size,
                                     node->aes_key, node->aes_iv, &existing_data);
        if (existing_size < 0) {
            return -EIO;
        }
    }

    // 更新明文数据
    int new_plaintext_size = offset + size;
    if (new_plaintext_size < existing_size) {
        new_plaintext_size = existing_size;
    }

    unsigned char *new_plaintext = malloc(new_plaintext_size);
    if (new_plaintext == NULL) {
        if (existing_data) free(existing_data);
        return -ENOMEM;
    }

    if (existing_data) {
        memcpy(new_plaintext, existing_data, existing_size);
        free(existing_data);
    } else {
        memset(new_plaintext, 0, new_plaintext_size);
    }

    memcpy(new_plaintext + offset, buf, size);

    // 加密数据
    unsigned char *encrypted_data = NULL;
    int encrypted_size = encrypt_data(new_plaintext, new_plaintext_size,
                                      node->aes_key, node->aes_iv, &encrypted_data);
    free(new_plaintext);

    if (encrypted_size < 0) {
        return -EIO;
    }

    // 更新节点
    if (node->data) free(node->data);
    node->data = (char *)encrypted_data;
    node->size = encrypted_size;
    node->plaintext_size = new_plaintext_size;

    // 打印加密数据
    printf("Encrypted data (size: %ld): ", node->size);
    for (int i = 0; i < node->size; i++) {
        printf("%02x", (unsigned char)node->data[i]);
    }
    printf("\n");

    return size;
}



// 实现 truncate 回调函数
static int memfs_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
    (void) fi;
    printf("truncate called for path: %s, size: %ld\n", path, size);

    memfs_node *node = find_node(path);
    if (node == NULL) {
        printf("truncate: node not found\n");
        return -ENOENT;
    }
    if (node->type != NODE_FILE) {
        printf("truncate: not a file\n");
        return -EISDIR;
    }

    // 读取已有的解密数据
    unsigned char *existing_data = NULL;
    int existing_size = 0;

    if (node->data != NULL && node->size > 0) {
        existing_size = decrypt_data((unsigned char *)node->data, node->size,
                                     node->aes_key, node->aes_iv, &existing_data);
        if (existing_size < 0) {
            printf("truncate: decryption failed\n");
            return -EIO;
        }
    }

    // 创建新的明文数据缓冲区
    unsigned char *new_plaintext = malloc(size);
    if (new_plaintext == NULL) {
        if (existing_data) free(existing_data);
        return -ENOMEM;
    }

    // 复制旧的明文数据或填充零
    if (existing_data) {
        memcpy(new_plaintext, existing_data, size < existing_size ? size : existing_size);
        if (size > existing_size) {
            memset(new_plaintext + existing_size, 0, size - existing_size);
        }
        free(existing_data);
    } else {
        memset(new_plaintext, 0, size);
    }

    // 加密新的明文数据
    unsigned char *encrypted_data = NULL;
    int encrypted_size = encrypt_data(new_plaintext, size,
                                      node->aes_key, node->aes_iv, &encrypted_data);
    free(new_plaintext);

    if (encrypted_size < 0) {
        printf("truncate: encryption failed\n");
        return -EIO;
    }

    // 释放旧的加密数据，存储新的加密数据
    if (node->data) free(node->data);
    node->data = (char *)encrypted_data;
    node->size = encrypted_size;
    node->plaintext_size = size;
    node->mtime = time(NULL);
    node->ctime = time(NULL);

    printf("truncate: new size is %ld\n", size);

    return 0;
}

// 实现 unlink 回调函数（删除文件）
static int memfs_unlink(const char *path) {
    printf("unlink called for path: %s\n", path);
    char *dup_path = strdup(path);
    char *file_name = strrchr(dup_path, '/');
    memfs_node *parent;

    if (file_name == dup_path) {
        parent = root;
        file_name++;
    } else {
        *file_name = '\0';
        parent = find_node(dup_path);
        file_name++;
    }

    if (parent == NULL || parent->type != NODE_DIR) {
        free(dup_path);
        return -ENOENT;
    }

    memfs_node *prev = NULL;
    memfs_node *current = parent->children;
    while (current != NULL) {
        if (strcmp(current->name, file_name) == 0 && current->type == NODE_FILE) {
            if (prev == NULL) {
                parent->children = current->next;
            } else {
                prev->next = current->next;
            }
            free(current->name);
            free(current->data);
            free(current);
            free(dup_path);
            return 0;
        }
        prev = current;
        current = current->next;
    }

    free(dup_path);
    return -ENOENT;
}

// 实现 rmdir 回调函数（删除目录）
static int memfs_rmdir(const char *path) {
    printf("rmdir called for path: %s\n", path);
    char *dup_path = strdup(path);
    char *dir_name = strrchr(dup_path, '/');
    memfs_node *parent;

    if (dir_name == dup_path) {
        parent = root;
        dir_name++;
    } else {
        *dir_name = '\0';
        parent = find_node(dup_path);
        dir_name++;
    }

    if (parent == NULL || parent->type != NODE_DIR) {
        free(dup_path);
        return -ENOENT;
    }

    memfs_node *prev = NULL;
    memfs_node *current = parent->children;
    while (current != NULL) {
        if (strcmp(current->name, dir_name) == 0 && current->type == NODE_DIR) {
            if (current->children != NULL) {
                free(dup_path);
                return -ENOTEMPTY;
            }
            if (prev == NULL) {
                parent->children = current->next;
            } else {
                prev->next = current->next;
            }
            free(current->name);
            free(current);
            free(dup_path);
            return 0;
        }
        prev = current;
        current = current->next;
    }

    free(dup_path);
    return -ENOENT;
}

// 实现 utimens 回调函数
static int memfs_utimens(const char *path, const struct timespec tv[2],
                         struct fuse_file_info *fi) {
    (void) fi;
    printf("utimens called for path: %s\n", path);

    memfs_node *node = find_node(path);
    if (node == NULL) {
        printf("utimens: node not found\n");
        return -ENOENT;
    }

    time_t now = time(NULL);

    // 处理 atime
    if (tv[0].tv_nsec == UTIME_NOW) {
        node->atime = now;
    } else if (tv[0].tv_nsec != UTIME_OMIT) {
        node->atime = tv[0].tv_sec;
    }

    // 处理 mtime
    if (tv[1].tv_nsec == UTIME_NOW) {
        node->mtime = now;
    } else if (tv[1].tv_nsec != UTIME_OMIT) {
        node->mtime = tv[1].tv_sec;
    }

    node->ctime = now;

    printf("utimens: atime set to %ld, mtime set to %ld\n", node->atime, node->mtime);

    return 0;
}

// 实现 chmod 回调函数
static int memfs_chmod(const char *path, mode_t mode, struct fuse_file_info *fi) {
    (void) fi;
    printf("chmod called for path: %s, mode: %o\n", path, mode);

    memfs_node *node = find_node(path);
    if (node == NULL) {
        printf("chmod: node not found\n");
        return -ENOENT;
    }

    node->mode = (node->mode & S_IFMT) | (mode & ~S_IFMT);
    node->ctime = time(NULL);

    printf("chmod: new mode is %o\n", node->mode);

    return 0;
}

// 实现 release 回调函数（关闭文件）
static int memfs_release(const char *path, struct fuse_file_info *fi) {
    printf("release called for path: %s\n", path);
    return 0;
}

// 定义 FUSE 操作结构体
static struct fuse_operations memfs_oper = {
    .getattr  = memfs_getattr,
    .readdir  = memfs_readdir,
    .mkdir    = memfs_mkdir,
    .mknod    = memfs_mknod,
    .create   = memfs_create,
    .open     = memfs_open,
    .read     = memfs_read,
    .write    = memfs_write,
    .truncate = memfs_truncate,
    .unlink   = memfs_unlink,
    .rmdir    = memfs_rmdir,
    .utimens  = memfs_utimens,
    .chmod    = memfs_chmod,
    .release  = memfs_release,
};

// 主函数
int main(int argc, char *argv[]) {
    // 初始化 OpenSSL（可选）
    //init_openssl();

    // 初始化根目录
    root = create_node("/", NODE_DIR, 0755, NULL);

    // 启动 FUSE 文件系统
    int ret = fuse_main(argc, argv, &memfs_oper, NULL);

    // 清理 OpenSSL（可选）
    //cleanup_openssl();

    return ret;
}

