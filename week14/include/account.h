#ifndef ACCOUNT_H
#define ACCOUNT_H

#define COIN_BASE "$"
#define MAX_ACCOUNTS 20

#include "utils.h"
#include "tx.h"

typedef struct {
    char pub[PUB_SIZE];
    int balance;
} Account;

extern int account_cnt;
extern Account accounts[MAX_ACCOUNTS];

int serialize_account(const Account *account, unsigned char *buffer, size_t buffer_size);
int deserialize_account(const unsigned char *buffer, Account *account);
void show_account(Account *account);
int eval_tx_to_account(const Tx *tx);

#endif // ACCOUNT_H