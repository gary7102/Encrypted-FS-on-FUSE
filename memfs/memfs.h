#ifndef MEMFS_H
#define MEMFS_H

#define FUSE_USE_VERSION 31

#include <fuse3/fuse.h>
#include <sys/types.h>
#include <time.h>

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

// declare global var. root 
extern memfs_node *root;

#endif // MEMFS_H

