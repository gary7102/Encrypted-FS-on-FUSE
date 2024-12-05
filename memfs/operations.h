#ifndef OPERATIONS_H
#define OPERATIONS_H

#include "memfs.h"

// FUSE 回调函数声明
int memfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi);
int memfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                  off_t offset, struct fuse_file_info *fi,
                  enum fuse_readdir_flags flags);
int memfs_mkdir(const char *path, mode_t mode);
int memfs_create(const char *path, mode_t mode, struct fuse_file_info *fi);
int memfs_mknod(const char *path, mode_t mode, dev_t rdev);
int memfs_open(const char *path, struct fuse_file_info *fi);
int memfs_read(const char *path, char *buf, size_t size, off_t offset,
               struct fuse_file_info *fi);
int memfs_write(const char *path, const char *buf, size_t size, off_t offset,
                struct fuse_file_info *fi);
int memfs_truncate(const char *path, off_t size, struct fuse_file_info *fi);
int memfs_unlink(const char *path);
int memfs_rmdir(const char *path);
int memfs_utimens(const char *path, const struct timespec tv[2],
                  struct fuse_file_info *fi);
int memfs_chmod(const char *path, mode_t mode, struct fuse_file_info *fi);
int memfs_release(const char *path, struct fuse_file_info *fi);

extern struct fuse_operations memfs_oper;

#endif // OPERATIONS_H

