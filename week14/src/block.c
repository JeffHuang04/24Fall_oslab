#include <string.h>
#include <pthread.h>
#include <openssl/sha.h>
#include "block.h"
#include "account.h"
#include "protocol.h"

int block_cnt;
Block blocks[MAX_BLOCKS];

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
    if (block_tx_cnt > MAX_BLOCK_TXS || block_tx_cnt <= 0 || output_len < HASH_SIZE) {
        return -1;
    }
    int current_level_cnt = MAX_BLOCK_TXS;
    unsigned char hashes[2 * MAX_BLOCK_TXS][SHA256_DIGEST_LENGTH];
    for (int i = 0; i < MAX_BLOCK_TXS; ++i) {
        if (i < block_tx_cnt) {
            if(hash_tx(&block_txs[i], hashes[i], SHA256_DIGEST_LENGTH)!=0){
                return -1;
            }
        } else {
            SHA256("", 0, hashes[i]);
        }
    }

    while (current_level_cnt > 1) {
        int next_level_cnt = (current_level_cnt + 1) / 2;
        for (int i = 0; i < next_level_cnt; ++i) {
            unsigned char cmb_hash[2 * SHA256_DIGEST_LENGTH] = {0};
            memcpy(cmb_hash, hashes[2 * i], SHA256_DIGEST_LENGTH);
            if (2 * i + 1 < current_level_cnt) {
                memcpy(cmb_hash + SHA256_DIGEST_LENGTH, hashes[2 * i + 1], SHA256_DIGEST_LENGTH);
            }
            SHA256(cmb_hash, 2 * SHA256_DIGEST_LENGTH, hashes[i]);
        }
        current_level_cnt = next_level_cnt;
    }

    unsigned char root_hash[SHA256_DIGEST_LENGTH];
    memcpy(root_hash, hashes[0], SHA256_DIGEST_LENGTH);
    base64_encode(root_hash, SHA256_DIGEST_LENGTH, output, output_len);
    return 0;
}//参考gpt实现

int verify_block(const Block *block) {
    char buffer[HASH_SIZE];
    merkle_tree_root(block->body.txs, block->body.tx_cnt, buffer, sizeof(buffer));
    return !strcmp(buffer, block->head.merkleRoot);
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
    blocks[block_cnt] = *block;
    block_cnt++;
    return 0;
}

int pack_txs_to_block(Block *block) {
    if (tx_cnt == 0) {
        return -1;
    }
    // TODO: week14
    memset(block->head.version, 0, sizeof(block->head.version));
    memset(block->head.prevHash, 0, sizeof(block->head.prevHash));
    block->head.difficulty = 0;
    block->head.nonce = 0;
    block->body.tx_cnt = 0;
    memset(block->body.txs, 0, sizeof(block->body.txs));
    int tx_to_pack = (tx_cnt < MAX_BLOCK_TXS) ? tx_cnt : MAX_BLOCK_TXS;
    for (int i = 0; i < tx_to_pack; i++) {
        block->body.txs[i] = txs[i]; // 将交易从txs转移到区块
    }
    block->body.tx_cnt = tx_to_pack;
    for (int i = 0; i < tx_to_pack; ++i) {
        Tx *tx = &block->body.txs[i];
        if (eval_tx_to_account(tx) < 0) {
            return -1; 
        }
    }
    if (merkle_tree_root(block->body.txs, tx_to_pack, block->head.merkleRoot, HASH_SIZE) < 0) {
        return -1;
    }
    for (int i = tx_to_pack; i < tx_cnt; i++) {
        txs[i - tx_to_pack] = txs[i];
    }
    tx_cnt -= tx_to_pack;
    return 0;
}