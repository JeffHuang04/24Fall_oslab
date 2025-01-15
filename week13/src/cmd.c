#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "cmd.h"
#include "protocol.h"
#include "node.h"

void help() {
    printf("[+] Usage123:\n");
    printf(" -   help\n");
    printf("      : Show help info\n");
    printf(" -   local\n");
    printf("      : Show local info\n");
    printf(" -   nodes\n");
    printf("      : Show node info\n");
    printf(" -   txs\n");
    printf("      : Show transaction info\n");
    printf(" -   hello\n");
    printf("      : Hello world to other nodes\n");
    printf(" -   new_transfer -t <to> -v <value>\n");
    printf("      : Create a new transfer: <local> -> <to> [<value>]\n");
    printf(" -   new_tx -f <from> -t <to> -v <value> -s <signature>\n");
    printf("      : Create a new transaction\n");
    printf(" -   quit\n");
    printf("      : Exit the game\n");
}

void show_local() {
    printf("[+] Local: %s:%s[%s]\n", ip_local, port_local, pub_local);
    printf("[+] PrvKey: %s\n", prv_local);
}

void show_nodes() {
    printf("[+] Total nodes: %d\n", node_cnt);
    for (int i=0; i < node_cnt; ++i) {
        printf(" [%d]:\n", i+1);
        show_node(&nodes[i]);
    }
}

void show_txs() {
    printf("[+] Total txs: %d\n", tx_cnt);
    for (int i=0; i<tx_cnt; ++i) {
        printf(" [%d]:\n", i+1);
        show_tx(&txs[i]);
    }
}

void hello() {
    // TODO
    Message msg;
    msg.type = NODE_BROADCAST;
    Node node_info;
    strncpy(node_info.ip, ip_local, sizeof(node_info.ip) - 1);
    strncpy(node_info.port, port_local, sizeof(node_info.port) - 1);
    strncpy(node_info.pub, pub_local, sizeof(node_info.pub) - 1);
    if (serialize_node(&node_info, msg.content, sizeof(msg.content)) != 0) {
        printf("Error serializing node info\n");
        return;
    }
    pthread_mutex_lock(&message_mutex);
    memcpy(&shared_message, &msg, sizeof(Message));
    pthread_cond_signal(&message_cond);
    pthread_mutex_unlock(&message_mutex);
    printf("Hello message broadcasted from node: %s:%s\n", ip_local, port_local);
}

void new_transfer(const char* to, const int value) {
    // TODO
    Tx tx;
    memset(&tx, 0, sizeof(tx));
    strncpy(tx.to, to, PUB_SIZE);
    tx.value = value;
    strncpy(tx.from, (const char*)pub_local, PUB_SIZE);
    char signature[SIG_SIZE];
    if (sign_tx(&tx, signature, sizeof(signature)) == 0) {
        strncpy(tx.signature, signature, SIG_SIZE);
        new_tx(&tx);
    }
    
}

void new_tx(const Tx *tx) {
    // TODO
    // if (verify_tx_signature(tx) != 1) {
    //     return;
    // }//先校验
    if(add_tx(tx)!=-1){
        unsigned char buffer[sizeof(Tx)];
        if (serialize_tx(tx, buffer, sizeof(buffer)) != 0) {
            return;
        }
        Message msg;
        msg.type = TX_BROADCAST;
        memcpy(msg.content, buffer, sizeof(buffer));
        pthread_mutex_lock(&message_mutex);
        memcpy(&shared_message, &msg, sizeof(Message));
        pthread_cond_signal(&message_cond);
        pthread_mutex_unlock(&message_mutex);
    }
    // printf("tx broadcasted");
}

void process_cmd(char *cmd) {
    char *token = strtok(cmd, " \n");
    if (token == NULL) {
        return;
    }

    if (strcmp(token, "help") == 0) {
        help();
    } else if (strcmp(token, "quit") == 0) {
        printf("[*] Exiting program...\n");
        exit(0);
    } else if (strcmp(token, "local") == 0) {
        show_local();
    } else if (strcmp(token, "nodes") == 0) {
        show_nodes();
    } else if (strcmp(token, "txs") == 0) {
        show_txs();
    } else if (strcmp(token, "hello") == 0) {
        hello();
    } else if (strcmp(token, "new_transfer") == 0) {
        char *to=NULL;
        int value=0;
        while ((token = strtok(NULL, " \n")) != NULL) {
            if (token[0] == '-') {
                if (token[1] == 't') {
                    token = strtok(NULL, " \n");
                    if (token != NULL) {
                        to = token;
                    }
                } else if (token[1] == 'v') {
                    token = strtok(NULL, " \n");
                    if (token != NULL) {
                        value = atoi(token);
                    }
                }
            }
        }
        if (to && value > 0) {
            new_transfer(to, value);
        } else {
            printf("[!] Invalid Parameters!\n");
            printf(" -  Type 'help' for usage\n");
        }
    } else if (strcmp(token, "new_tx") == 0) {
        char *from=NULL, *to=NULL, *signature=NULL;
        int value=0;
        while ((token = strtok(NULL, " \n")) != NULL) {
            if (token[0] == '-') {
                if (token[1] == 'f') {
                    token = strtok(NULL, " \n");
                    if (token != NULL) {
                        from = token;
                    }
                } else if (token[1] == 't') {
                    token = strtok(NULL, " \n");
                    if (token != NULL) {
                        to = token;
                    }
                } else if (token[1] == 's') {
                    token = strtok(NULL, " \n");
                    if (token != NULL) {
                        signature = token;
                    }
                } else if (token[1] == 'v') {
                    token = strtok(NULL, " \n");
                    if (token != NULL) {
                        value = atoi(token);
                    }
                }
            }
        }
        if (from && to && signature && value > 0) {
            Tx tx;
            tx.value = value;
            snprintf(tx.from, PUB_SIZE, "%s", from);
            snprintf(tx.to, PUB_SIZE, "%s", to);
            snprintf(tx.signature, SIG_SIZE, "%s", signature);
            new_tx(&tx);
        } else {
            printf("[!] Invalid Parameters!\n");
            printf(" -  Type 'help' for usage\n");
        }
    } else {
        printf("[!] Unknown command: %s\n", token);
        printf(" -  Type 'help' for usage\n");
    }
}