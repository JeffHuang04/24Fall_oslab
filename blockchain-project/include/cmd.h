#ifndef CMD_H
#define CMD_H

#define CMD_SIZE 1024
#define MAX_ARGC 10

#include "tx.h"
#include "account.h"
#include "block.h"

void process_cmd(char *input);
void help();
void show_nodes();
void show_txs();
void show_accounts();
void show_blocks();
void hello();
void pack();
void cb_transfer(const char* to, const int value);
void new_transfer(const char* to, const int value, const int fee);
void new_tx(const Tx *tx);

#endif // CMD_H