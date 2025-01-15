#include <string.h>
#include <pthread.h>
#include "tx.h"
#include "protocol.h"
#include "node.h"
#include "utils.h"
#include "account.h"

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
    printf(" -  id   : %d\n", tx->id);
    printf(" -  from : %s\n", tx->from);
    printf(" -  to   : %s\n", tx->to);
    printf(" -  value: %d\n", tx->value);
    printf(" -  fee  : %d\n", tx->fee);
    printf(" -  sig  : %s\n", tx->signature);
}

int sign_tx(const Tx *tx, char *signature, size_t signature_len) {
    char buffer[2*PUB_SIZE+20];
    snprintf(buffer, sizeof(buffer), "%u|%s|%s|%d|%d", tx->id, tx->from, tx->to, tx->value, tx->fee);
    if (sign_message(prv_local, buffer, signature, signature_len) < 0) {
        return -1;
    }
    return 0;
}

int verify_tx_signature(const Tx *tx) {
    if (strcmp(tx->from, COIN_BASE) == 0) {
        return 1;
    }
    char buffer[2*PUB_SIZE+20];
    snprintf(buffer, sizeof(buffer), "%u|%s|%s|%d|%d", tx->id, tx->from, tx->to, tx->value, tx->fee);
    return verify_signature(tx->from, buffer, tx->signature);
}

int send_tx(const Tx *tx) {
    // TODO: week13

    return 0;
}

int add_tx(const Tx *tx) {
    if (tx_cnt == MAX_TXS) {
        return -1;
    }
    // TODO: week13

    return 0;
}