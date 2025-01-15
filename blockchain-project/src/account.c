#include <string.h>
#include <pthread.h>
#include "account.h"
#include "tx.h"
#include "protocol.h"
#include "node.h"
#include "utils.h"

int account_cnt;
Account accounts[MAX_ACCOUNTS];

int serialize_account(const Account *account, unsigned char *buffer, size_t buffer_size) {
    if (buffer_size < sizeof(Account)) {
        return -1;
    }
    memcpy(buffer, account, sizeof(Account));
    return 0;
}

int deserialize_account(const unsigned char *buffer, Account *account) {
    memcpy(account, buffer, sizeof(Account));
    return 0;
}

void show_account(Account *account) {
    printf(" -  [%s]:%d\n", account->pub, account->balance);
}

int eval_tx_to_account(const Tx *tx) {
    // TODO: week14
    
    return 0;
}