#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "cmd.h"
#include "protocol.h"
#include "node.h"

void help() {
    printf("[+] Usage:\n");
    printf(" -   help\n");
    printf("      : Show help info\n");
    printf(" -   local\n");
    printf("      : Show local info\n");
    printf(" -   nodes\n");
    printf("      : Show node info\n");
    printf(" -   txs\n");
    printf("      : Show transaction info\n");
    printf(" -   accounts\n");
    printf("      : Show account info\n");
    printf(" -   blocks\n");
    printf("      : Show block info\n");
    printf(" -   hello\n");
    printf("      : Hello world to other nodes\n");
    printf(" -   pack\n");
    printf("      : Pack up txs into a block\n");
    printf(" -   cb_transfer -t <to> -v <value>\n");
    printf("      : Create a coinbase transfer: <local> -> <to> [<value>]\n");
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

void show_accounts() {
    printf("[+] Total accounts: %d\n", account_cnt);
    for (int i=0; i<account_cnt; ++i) {
        printf(" [%d]:\n", i+1);
        show_account(&accounts[i]);
    }
}

void show_blocks() {
    printf("[+] Total blocks: %d\n", block_cnt);
    for (int i=0; i<block_cnt; ++i) {
        printf(" [%d]:\n", i+1);
        show_block(&blocks[i]);
    }
}

void hello() {
    // TODO: week13
}

void new_transfer(const char* to, const int value) {
    // TODO: week13
}

void new_tx(const Tx *tx) {
    // TODO: week13
}

void pack() {
    // TODO: week14
}

void cb_transfer(const char* to, const int value) {
    Tx tx;
    tx.id = rand();
    tx.value = value;
    snprintf(tx.from, PUB_SIZE, "%s", COIN_BASE);
    snprintf(tx.to, PUB_SIZE, "%s", to);
    snprintf(tx.signature, SIG_SIZE, "%s", COIN_BASE);
    eval_tx_to_account(&tx);
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
    } else if (strcmp(token, "accounts") == 0) {
        show_accounts();
    } else if (strcmp(token, "blocks") == 0) {
        show_blocks();
    } else if (strcmp(token, "hello") == 0) {
        hello();
    } else if (strcmp(token, "pack") == 0) {
        pack();
    } else if (strcmp(token, "cb_transfer") == 0) {
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
            cb_transfer(to, value);
        } else {
            printf("[!] Invalid Parameters!\n");
            printf(" -  Type 'help' for usage\n");
        }
    } else if (strcmp(token, "new_transfer") == 0) {
        char *to=NULL;
        int value=0, fee=0;
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
                } else if (token[1] == 'x') {
                    token = strtok(NULL, " \n");
                    if (token != NULL) {
                        fee = atoi(token);
                    }
                }
            }
        }
        if (to && value > 0 && fee >= 0) {
            new_transfer(to, value, fee);
        } else {
            printf("[!] Invalid Parameters!\n");
            printf(" -  Type 'help' for usage\n");
        }
    } else if (strcmp(token, "new_tx") == 0) {
        char *from=NULL, *to=NULL, *signature=NULL;
        int value=0, fee=0;
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
                } else if (token[1] == 'x') {
                    token = strtok(NULL, " \n");
                    if (token != NULL) {
                        fee = atoi(token);
                    }
                }
            }
        }
        if (from && to && signature && value > 0 && fee >= 0) {
            Tx tx;
            tx.id = rand();
            tx.value = value;
            tx.fee = fee;
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