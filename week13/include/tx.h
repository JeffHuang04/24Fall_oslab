#ifndef TX_H
#define TX_H

#define MAX_TXS 500
#define MAX_ACCOUNTS 100

#include "utils.h"

typedef struct {
    int value;
    char from[PUB_SIZE];
    char to[PUB_SIZE];
    char signature[SIG_SIZE];
} Tx;

extern int tx_cnt;
extern Tx txs[MAX_TXS];

int serialize_tx(const Tx *tx, unsigned char *buffer, size_t buffer_size);
int deserialize_tx(const unsigned char *buffer, Tx *tx);
void show_tx(const Tx *tx);
int sign_tx(const Tx *tx, char *signature, size_t signature_len);
int verify_tx_signature(const Tx *tx);
int verify_tx_value(const Tx *tx);
int send_tx(const Tx *tx);
int add_tx(const Tx *tx);
int eval_tx(const Tx *tx);

#endif // TX_H