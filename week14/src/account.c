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
    if(strcmp(tx->from,COIN_BASE) == 0){
        for(int i = 0;i < account_cnt;i++){
            if(strcmp(accounts[i].pub,tx->to) == 0){
                accounts[i].balance += tx->value;
                return 0;
            }
        }
        //不存在接受账户则创建
        Account new_account;
        snprintf(new_account.pub, PUB_SIZE, "%s", tx->to);
        new_account.balance = tx->value;
        accounts[account_cnt++] = new_account;
        return 0;
    }
    int from_index = -1, to_index = -1;
    for (int i = 0; i < account_cnt; i++) {
        if (strcmp(accounts[i].pub, tx->from) == 0) {
            from_index = i;
            break;
        }
    }
    for (int i = 0; i < account_cnt; i++) {
        if (strcmp(accounts[i].pub, tx->to) == 0) {
            to_index = i;
            break;
        }
    }
    if (from_index == -1||accounts[from_index].balance < tx->value) {
        return -1;
    }
    accounts[from_index].balance -= tx->value;
    if (to_index == -1) {
        if (account_cnt < MAX_ACCOUNTS) {
            Account new_account;
            snprintf(new_account.pub, PUB_SIZE, "%s", tx->to);
            new_account.balance = tx->value;
            accounts[account_cnt++] = new_account;
        } else {
            return -1;
        }
    } else {
        accounts[to_index].balance += tx->value;
    }
    return 0;
}