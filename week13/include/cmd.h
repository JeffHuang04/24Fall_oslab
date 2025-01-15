#ifndef CMD_H
#define CMD_H

#define CMD_SIZE 256
#define MAX_ARGC 10

#include "tx.h"

void process_cmd(char *input);
void help();
void show_nodes();
void show_txs();
void hello();
void new_transfer(const char* to, const int value);
void new_tx(const Tx *tx);

#endif // CMD_H