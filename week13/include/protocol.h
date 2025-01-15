#ifndef PROTOCOL_H
#define PROTOCOL_H

#define CONTENT_SIZE 4096

typedef enum {
    MSG_BROADCAST,
    NODE_BROADCAST,
    TX_BROADCAST,
} MessageType;

typedef struct {
    MessageType type;
    unsigned char content[CONTENT_SIZE];
} Message;

extern int sender_socket, receiver_socket;

extern Message shared_message;
extern pthread_mutex_t message_mutex;
extern pthread_cond_t message_cond;

int init_socket();
int sender_connect(const char *ip, const char *port);
int send_message(Message *msg);
int receive_message(Message *msg);
int serialize_message(const Message *msg, unsigned char *buffer, size_t buffer_size);
int deserialize_message(const unsigned char *buffer, Message *msg);

#endif // PROTOCOL_H