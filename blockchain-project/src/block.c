#include <string.h>
#include <pthread.h>
#include <openssl/sha.h>
#include "block.h"
#include "node.h"
#include "account.h"
#include "protocol.h"

int difficulty;
int block_cnt = 1;
Block blocks[MAX_BLOCKS] = {
    {
        .head.version = "bc2024",
        .head.prevHash = "#",
        .head.merkleRoot = "#",
        .head.difficulty = 0,
        .head.nonce = 0,
        .body.tx_cnt = 0,
        .body.txs = {{0}}
    }
};

int serialize_block(const Block *block, unsigned char *buffer, size_t buffer_size) {
    if (buffer_size < sizeof(Block)) {
        return -1;
    }
    memcpy(buffer, block, sizeof(Block));
    return 0;
}

int deserialize_block(const unsigned char *buffer, Block *block) {
    memcpy(block, buffer, sizeof(Block));
    return 0;
}

void show_block(const Block *block) {
    printf(" -  version    : %s\n", block->head.version);
    printf(" -  prevHash   : %s\n", block->head.prevHash);
    printf(" -  difficulty : %d\n", block->head.difficulty);
    printf(" -  nonce      : %d\n", block->head.nonce);
    printf(" -  merkleRoot : %s\n", block->head.merkleRoot);
    printf(" -  tx_cnt     : %d\n", block->body.tx_cnt);
}

int hash_tx(const Tx *tx, unsigned char *output, size_t output_len) {
    if (output_len < SHA256_DIGEST_LENGTH) {
        return -1;
    }
    char buffer[2*PUB_SIZE+SIG_SIZE+20];
    snprintf(buffer, sizeof(buffer), "%d|%s|%s|%s|%d", tx->id, tx->from, tx->to, tx->signature, tx->value);
    SHA256((unsigned char*)buffer, strlen(buffer), output);
    return 0;
}

int merkle_tree_root(const Tx *block_txs, const int block_tx_cnt, char *output, size_t output_len) {
    // TODO: week14

    return 0;
}

int verify_block(const Block *block) {
    // TODO: week15

    return 1;
}

int send_block(const Block *block) {
    // TODO: week14

    return 0;
}

int add_block(const Block *block) {
    if (block_cnt == MAX_BLOCKS) {
        return -1;
    }
    // TODO: week14

    return 0;
}

int pack_txs_to_block(Block *block) {
    // if (tx_cnt == 0) {
    //     return -1;
    // }
    // TODO: week15

    return 0;
}

int hash_block(const Block *block, unsigned char *output, size_t output_len) {
    if (output_len < SHA256_DIGEST_LENGTH) {
        return -1;
    }
    char buffer[2*HASH_SIZE+30];
    snprintf(buffer, sizeof(buffer), "%s|%s|%s|%d|%d", block->head.version, block->head.prevHash, block->head.merkleRoot, block->head.difficulty, block->head.nonce);
    SHA256((unsigned char*)buffer, strlen(buffer), output);
    return 0;
}

int check(const unsigned char *buffer, const int difficulty) {
    int l = (int)(difficulty/8);
    for (int i=0; i<l; ++i) {
        if (buffer[i]) {
            return 0;
        }
    }
    if ((difficulty % 8) && (buffer[l] >> (difficulty % 8))) {
        return 0;
    }
    return 1;
}