#include <string.h>
#include <pthread.h>
#include <nanomsg/nn.h>
#include <nanomsg/bus.h>
#include "protocol.h"
#include "node.h"

int sender_socket, receiver_socket;

int init_socket() {
    char target[50];

    receiver_socket = nn_socket(AF_SP, NN_BUS);
    if (receiver_socket < 0) {
        perror("nn_sender_socket failed");
        return -1;
    }
    snprintf(target, sizeof(target), "tcp://%.15s:%.5s", ip_local, port_local);
    if (nn_bind(receiver_socket, target) < 0) {
        perror("nn_bind_sender_socket failed");
        return -1;
    }

    sender_socket = nn_socket(AF_SP, NN_BUS);
    if (sender_socket < 0) {
        perror("nn_receiver_socket failed");
        return -1;
    }
    for(int i = 0; i < node_cnt; ++i) {
        if (sender_connect(nodes[i].ip, nodes[i].port) < 0) {
            perror("nn_connect_receiver_socket failed");
            return -1;
        }
    }

    return 0;
}

int sender_connect(const char* ip, const char* port) {
    char target[50];
    snprintf(target, sizeof(target), "tcp://%.15s:%.5s", ip, port);
    if (nn_connect(sender_socket, target) < 0) {
        return -1;
    }
    return 0;
}

int serialize_message(const Message *msg, unsigned char *buffer, size_t buffer_size) {
    if (buffer_size < sizeof(Message)) {
        return -1;
    }
    memcpy(buffer, msg, sizeof(Message));
    return 0;
}

int deserialize_message(const unsigned char *buffer, Message *msg) {
    memcpy(msg, buffer, sizeof(Message));
    return 0;
}

int send_message(Message *msg) {
    unsigned char buffer[CONTENT_SIZE + 100];
    if (serialize_message(msg, buffer, sizeof(buffer)) < 0) {
        return -1;
    }

    if (nn_send(sender_socket, buffer, sizeof(buffer), 0) < 0) {
        return -1;
    }
    return 0;
}

int receive_message(Message *msg) {
    unsigned char buffer[CONTENT_SIZE + 100];
    if (nn_recv(receiver_socket, buffer, sizeof(buffer), 0) < 0) {
        return -1;
    }

    if (deserialize_message(buffer, msg) < 0) {
        return -1;
    }
    return 0;
}