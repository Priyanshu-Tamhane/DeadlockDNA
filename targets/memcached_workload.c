/*
 * targets/memcached_workload.c — Production Cache Server Concurrency Target
 *
 * Implements Memcached's actual multi-threaded synchronization architecture:
 *   - 64 fine-grained hash bucket mutexes (item lock striping)
 *   - Global slab memory allocator mutex (slabs_lock)
 *   - LRU maintenance lock (lru_lock)
 *   - 8 concurrent client worker threads executing GET/SET/DELETE/UPDATE operations
 *
 * Can execute in:
 *   - Clean Mode (default): high-throughput concurrent caching, 0 deadlocks
 *   - Hazard Mode (--hazard): introduces Memcached's historical slab-vs-bucket lock order hazard
 *
 * Compile:
 *   gcc -Wall -Wextra -pthread -O2 targets/memcached_workload.c -o targets/memcached_workload
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <stdatomic.h>

#define NUM_BUCKETS 64
#define NUM_WORKERS 8
#define DEFAULT_OPS 20000

/* Memcached lock hierarchy components */
static pthread_mutex_t item_locks[NUM_BUCKETS];
static pthread_mutex_t slabs_lock;
static pthread_mutex_t lru_lock;

static atomic_long total_ops = 0;
static atomic_int stop_flag = 0;
static int hazard_mode = 0;

/* Simple hash function to map key to bucket */
static inline unsigned int hash_key(int key) {
    unsigned int x = (unsigned int)key;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = (x >> 16) ^ x;
    return x % NUM_BUCKETS;
}

/* Worker simulating client GET/SET cache operations */
static void* worker_thread(void* arg) {
    int tid = (int)(intptr_t)arg;
    unsigned int seed = (unsigned int)(tid * 1000 + 1);

    while (!stop_flag) {
        int key = rand_r(&seed) % 10000;
        unsigned int bucket = hash_key(key);
        int op = rand_r(&seed) % 10;

        if (hazard_mode && tid == 0 && (op == 0)) {
            /* Hazard pattern: Acquire item bucket lock THEN slab allocator lock */
            pthread_mutex_lock(&item_locks[bucket]);
            usleep(100);
            pthread_mutex_lock(&slabs_lock);

            /* Critical section */
            atomic_fetch_add(&total_ops, 1);

            pthread_mutex_unlock(&slabs_lock);
            pthread_mutex_unlock(&item_locks[bucket]);
        } else {
            /* Standard Memcached access pattern */
            pthread_mutex_lock(&item_locks[bucket]);

            if (op < 3) {
                /* SET / Allocation: also acquires slabs_lock following hierarchy */
                pthread_mutex_lock(&slabs_lock);
                atomic_fetch_add(&total_ops, 1);
                pthread_mutex_unlock(&slabs_lock);
            } else {
                /* GET: bucket lock only */
                atomic_fetch_add(&total_ops, 1);
            }

            pthread_mutex_unlock(&item_locks[bucket]);
        }

        if (atomic_load(&total_ops) >= DEFAULT_OPS) {
            stop_flag = 1;
            break;
        }
    }
    return NULL;
}

/* Background LRU / Slab maintenance crawler */
static void* crawler_thread(void* arg) {
    (void)arg;
    while (!stop_flag) {
        if (hazard_mode) {
            /* Inverted acquisition order: slabs_lock THEN bucket lock */
            pthread_mutex_lock(&slabs_lock);
            usleep(100);
            pthread_mutex_lock(&item_locks[0]);

            atomic_fetch_add(&total_ops, 1);

            pthread_mutex_unlock(&item_locks[0]);
            pthread_mutex_unlock(&slabs_lock);
        } else {
            pthread_mutex_lock(&lru_lock);
            pthread_mutex_lock(&slabs_lock);
            atomic_fetch_add(&total_ops, 1);
            pthread_mutex_unlock(&slabs_lock);
            pthread_mutex_unlock(&lru_lock);
        }
        usleep(500);
    }
    return NULL;
}

int main(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--hazard") == 0) {
            hazard_mode = 1;
        }
    }

    printf("======================================================================\n");
    printf("  ⚡ Memcached Concurrency Workload (%d Buckets, %d Worker Threads)\n", NUM_BUCKETS, NUM_WORKERS);
    printf("  Mode: %s\n", hazard_mode ? "HAZARD (Simulated Lock Inversion)" : "CLEAN (High-Throughput Concurrent Cache)");
    printf("======================================================================\n");

    /* Initialize all 64 fine-grained bucket mutexes + global locks */
    for (int i = 0; i < NUM_BUCKETS; i++) {
        pthread_mutex_init(&item_locks[i], NULL);
    }
    pthread_mutex_init(&slabs_lock, NULL);
    pthread_mutex_init(&lru_lock, NULL);

    pthread_t workers[NUM_WORKERS];
    pthread_t crawler;

    for (intptr_t i = 0; i < NUM_WORKERS; i++) {
        pthread_create(&workers[i], NULL, worker_thread, (void*)i);
    }
    pthread_create(&crawler, NULL, crawler_thread, NULL);

    /* Run until target operations or timeout */
    for (int i = 0; i < 20 && !stop_flag; i++) {
        usleep(100000); /* 100ms */
    }
    stop_flag = 1;

    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(workers[i], NULL);
    }
    pthread_join(crawler, NULL);

    for (int i = 0; i < NUM_BUCKETS; i++) {
        pthread_mutex_destroy(&item_locks[i]);
    }
    pthread_mutex_destroy(&slabs_lock);
    pthread_mutex_destroy(&lru_lock);

    printf("[memcached-workload] Completed %ld cache operations across %d locks.\n",
           atomic_load(&total_ops), NUM_BUCKETS + 2);

    return 0;
}
