/*
 * workload_no_lock.c — Pure Computation Baseline Workload
 * DeadlockDNA — benchmarks/workloads/
 *
 * Spawns multiple threads doing mathematical computation without any locks.
 * Used as a baseline for measuring CPU overhead and ensuring 0 false positives.
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#define NUM_THREADS 4
#define ITERATIONS 5000000

static void *compute_worker(void *arg) {
    long id = (long)arg;
    volatile unsigned long sum = 0;
    for (unsigned long i = 0; i < ITERATIONS; i++) {
        sum += (i * 33) ^ id;
    }
    return NULL;
}

int main(void) {
    pthread_t threads[NUM_THREADS];

    for (long i = 0; i < NUM_THREADS; i++) {
        if (pthread_create(&threads[i], NULL, compute_worker, (void *)i) != 0) {
            perror("pthread_create");
            return 1;
        }
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}

