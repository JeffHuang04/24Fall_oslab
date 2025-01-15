#ifndef BLOCK_H
#define BLOCK_H

#include "utils.h"
#include "tx.h"

#define MAX_BLOCKS 20
#define MAX_BLOCK_TXS 16

typedef struct {
    char version[10];
    char prevHash[HASH_SIZE];
    char merkleRoot[HASH_SIZE];
    int difficulty;
    int nonce;
} BlockHead;

typedef struct {
    int tx_cnt;
    Tx txs[MAX_BLOCK_TXS];
} BlockBody;

typedef struct {
    BlockHead head;
    BlockBody body;
} Block;

extern int difficulty;
extern int block_cnt;
extern Block blocks[MAX_BLOCKS];

int serialize_block(const Block *block, unsigned char *buffer, size_t buffer_size);
int deserialize_block(const unsigned char *buffer, Block *block);
void show_block(const Block *block);
int merkle_tree_root(const Tx *txs, const int tx_cnt, char *output, size_t output_len);
int verify_block(const Block *block);
int send_block(const Block *block);
int add_block(const Block *block);
int pack_txs_to_block(Block *block);
int hash_block(const Block *block, unsigned char *output, size_t output_len);

#endif // BLOCK_H