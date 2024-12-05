#include "node.h"
#include "encryption.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

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

