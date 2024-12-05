#include "operations.h"
#include "node.h"
#include "encryption.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

// 实现 getattr 回调函数
int memfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
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
int memfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
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
int memfs_mkdir(const char *path, mode_t mode) {
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
int memfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
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
int memfs_mknod(const char *path, mode_t mode, dev_t rdev) {
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
int memfs_open(const char *path, struct fuse_file_info *fi) {
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

// 实现 read 回调函数
int memfs_read(const char *path, char *buf, size_t size, off_t offset,
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

// 实现 write 回调函数
int memfs_write(const char *path, const char *buf, size_t size, off_t offset,
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
int memfs_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
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

// 实现 unlink 回调函数
int memfs_unlink(const char *path) {
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

// 实现 rmdir 回调函数
int memfs_rmdir(const char *path) {
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
int memfs_utimens(const char *path, const struct timespec tv[2],
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
int memfs_chmod(const char *path, mode_t mode, struct fuse_file_info *fi) {
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

// 实现 release 回调函数
int memfs_release(const char *path, struct fuse_file_info *fi) {
    printf("release called for path: %s\n", path);
    return 0;
}

// 定义 FUSE 操作结构体
struct fuse_operations memfs_oper = {
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

