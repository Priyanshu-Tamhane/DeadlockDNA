/*
 * workload_contention.c — Non-Deadlocking Contention Workload
 * DeadlockDNA — benchmarks/workloads/
 *
 * Multiple threads contend heavily for a single shared mutex.
 * High contention triggers kernel futex waits, but there is NO circular wait.
 * Must produce zero deadlock detections (0% false positives).
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define NUM_THREADS 4
#define ITERATIONS 100000

static pthread_mutex_t shared_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile long shared_counter = 0;

static void *contention_worker(void *arg) {
    (void)arg;
    for (int i = 0; i < ITERATIONS; i++) {
        pthread_mutex_lock(&shared_lock);
        shared_counter++;
        pthread_mutex_unlock(&shared_lock);
    }
    return NULL;
}

int main(void) {
    pthread_t threads[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_create(&threads[i], NULL, contention_worker, NULL) != 0) {
            perror("pthread_create");
            return 1;
        }
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}

