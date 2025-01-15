#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <nanomsg/nn.h>
#include <nanomsg/bus.h>
#include "node.h"
#include "protocol.h"
#include "cmd.h"
#include "tx.h"
#include "block.h"

void *send_thread_func() {
    // TODO
    
    while (1) {
        // TODO

    }
    return NULL;
}

void *receive_thread_func() {
    // TODO

    while (1) {
        // TODO

    }
    return NULL;
}

void *cmd_thread_func() {
    char cmd[CMD_SIZE];
    while (1) {
        if (fgets(cmd, sizeof(cmd), stdin) == NULL) {
            break;
        }
        printf("$ %s", cmd);
        process_cmd(cmd);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <node>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    snprintf(node_local, sizeof(node_local), "%s", argv[argc-1]);
    srand(node_local[4]);

    // config init
    if (init_config() < 0) {
        exit(EXIT_FAILURE);
    }

    // socket init
    if (init_socket() < 0) {
        exit(EXIT_FAILURE);
    }

    pthread_t send_thread, receive_thread, cmd_thread;
    pthread_create(&send_thread, NULL, send_thread_func, NULL);
    pthread_create(&receive_thread, NULL, receive_thread_func, NULL);
    pthread_create(&cmd_thread, NULL, cmd_thread_func, NULL);

    pthread_join(send_thread, NULL);
    pthread_join(receive_thread, NULL);
    pthread_join(cmd_thread, NULL);

    nn_shutdown(sender_socket, 0);
    nn_shutdown(receiver_socket, 0);
    return 0;
}