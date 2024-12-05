#ifndef NODE_H
#define NODE_H

#include "memfs.h"

// 辅助函数：创建新节点
memfs_node *create_node(const char *name, node_type type, mode_t mode, memfs_node *parent);

// 查找节点的函数
memfs_node *find_node(const char *path);

#endif // NODE_H

