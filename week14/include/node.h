#ifndef NODE_H
#define NODE_H

#include "utils.h"

#define MAX_NODES 100

typedef struct {
    char ip[16];
    char port[6];
    char pub[PUB_SIZE];
} Node;

extern char node_local[10], ip_local[16], port_local[6], pub_local[PUB_SIZE], prv_local[PRV_SIZE];
extern int isWorker;
extern int node_cnt;
extern Node nodes[MAX_NODES];

int init_config();
int handler(void* user, const char* section, const char* name, const char* value);
int serialize_node(const Node *node, unsigned char *buffer, size_t buffer_size);
int deserialize_node(const unsigned char *buffer, Node *node);
void show_node(const Node *node);
int send_node(const Node *node);
int add_node(const Node *node);

#endif // NODE_H