#include "philosopher.h"
#define PHILOSOPHER_NUM 5

int forks[PHILOSOPHER_NUM];
int mutex;

void init() {
    for (int i = 0; i < PHILOSOPHER_NUM; ++i) {
        forks[i] = sem_open(1);
    }
    mutex = sem_open(1);
}

void philosopher(int id) {
    while (1) {
        think(id);
        P(mutex);
        P(forks[id]);
        P(forks[(id + 1) % PHILOSOPHER_NUM]);
        V(mutex);
        eat(id);
        V(forks[id]);
        V(forks[(id + 1) % PHILOSOPHER_NUM]);
    }
}
