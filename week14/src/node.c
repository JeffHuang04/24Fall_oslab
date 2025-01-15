#include <string.h>
#include <pthread.h>
#include <ini.h>
#include "node.h"
#include "protocol.h"

char node_local[10], ip_local[16], port_local[6], pub_local[PUB_SIZE], prv_local[PRV_SIZE];
int isWorker;
int node_cnt;
Node nodes[MAX_NODES];

int init_config() {
    char config_path[50];
    snprintf(config_path, sizeof(config_path), "build/config/%s/local.ini", node_local);
    if (ini_parse(config_path, handler, NULL) < 0) {
        return -1;
    }
    snprintf(config_path, sizeof(config_path), "build/config/%s/network.ini", node_local);
    if (ini_parse(config_path, handler, NULL) < 0) {
        return -1;
    }
    return 0;
}

int handler(void* user, const char* section, const char* name, const char* value) {
    if (strcmp(section, "local") == 0) {
        if (strcmp(name, "ip") == 0) {
            snprintf(ip_local, 16, "%.15s", value);
        } else if (strcmp(name, "port") == 0) {
            snprintf(port_local, 6, "%.5s", value);
        } else if (strcmp(name, "pub") == 0) {
            snprintf(pub_local, PUB_SIZE, "%s", value);
        } else if (strcmp(name, "prv") == 0) {
            snprintf(prv_local, PRV_SIZE, "%s", value);
        } else if (strcmp(name, "isWorker") == 0) {
            isWorker = atoi(value);
        }
    } else {
        if (node_cnt == MAX_NODES) {
            return 1;
        }
        if (strcmp(name, "ip") == 0) {
            snprintf(nodes[node_cnt].ip, 16, "%.15s", value);
        } else if (strcmp(name, "port") == 0) {
            snprintf(nodes[node_cnt].port, 6, "%.5s", value);
        } else if (strcmp(name, "pub") == 0) {
            snprintf(nodes[node_cnt].pub, PUB_SIZE, "%s", value);
            ++node_cnt;
        }
    }
    return 1;
}

int serialize_node(const Node *node, unsigned char *buffer, size_t buffer_size) {
    if (buffer_size < sizeof(Node)) {
        return -1;
    }
    memcpy(buffer, node, sizeof(Node));
    return 0;
}

int deserialize_node(const unsigned char *buffer, Node *node) {
    memcpy(node, buffer, sizeof(Node));
    return 0;
}

void show_node(const Node *node) {
    printf(" -   %s:%s[%s]\n", node->ip, node->port, node->pub);
}

int send_node(const Node *node) {
    // TODO: week13

    return 0;
}

int add_node(const Node *node) {
    // TODO: week13
    memcpy(&nodes[node_cnt], node, sizeof(Node));
    node_cnt++;
    return 0;
}