#include <string.h>
#include <pthread.h>
#include "tx.h"
#include "protocol.h"
#include "node.h"
#include "utils.h"

int tx_cnt;
Tx txs[MAX_TXS];

int serialize_tx(const Tx *tx, unsigned char *buffer, size_t buffer_size) {
    if (buffer_size < sizeof(Tx)) {
        return -1;
    }
    memcpy(buffer, tx, sizeof(Tx));
    return 0;
}

int deserialize_tx(const unsigned char *buffer, Tx *tx) {
    memcpy(tx, buffer, sizeof(Tx));
    return 0;
}

void show_tx(const Tx *tx) {
    printf(" -  from : %s\n", tx->from);
    printf(" -  to   : %s\n", tx->to);
    printf(" -  value: %d\n", tx->value);
    printf(" -  sig  : %s\n", tx->signature);
}

int sign_tx(const Tx *tx, char *signature, size_t signature_len) {
    // TODO
    char message[2*PUB_SIZE+10];
    snprintf(message, sizeof(message), "%s|%s|%d", tx->from, tx->to, tx->value);
    return sign_message((const char *)prv_local, message, signature, signature_len);
}

int verify_tx_signature(const Tx *tx) {
    char buffer[2*PUB_SIZE+10];
    snprintf(buffer, sizeof(buffer), "%s|%s|%d", tx->from, tx->to, tx->value);
    // printf("test1\n");
    return verify_signature(tx->from, buffer, tx->signature);
}

int verify_tx_value(const Tx *tx) {
    if (tx->value <= 0) {
        return 0;
    }
    return 1;
}

int send_tx(const Tx *tx) {
    // TODO
    return 0;
}

int add_tx(const Tx *tx) {
    if (tx_cnt == MAX_TXS) {
        return -1;
    }
    if (verify_tx_signature(tx) != 1) {
        return -1;
    }//先校验
    txs[tx_cnt] = *tx;
    tx_cnt++;
    return 0;
}