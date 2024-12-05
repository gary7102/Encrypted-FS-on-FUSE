#include "memfs.h"
#include "node.h"
#include "operations.h"

memfs_node *root;

int main(int argc, char *argv[]) {
    // 初始化根目录
    root = create_node("/", NODE_DIR, 0755, NULL);

    // 启动 FUSE 文件系统
    return fuse_main(argc, argv, &memfs_oper, NULL);
}

