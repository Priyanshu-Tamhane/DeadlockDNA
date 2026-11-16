/*
 * workload_stress.c — Repeated Acquire/Release Stress Workload
 * DeadlockDNA — benchmarks/workloads/
 *
 * Multiple threads acquire distinct non-conflicting mutexes rapidly.
 * Evaluates event pipeline throughput and stress without circular wait.
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#define NUM_THREADS 4
#define ITERATIONS 200000

static pthread_mutex_t locks[NUM_THREADS];
static volatile long counters[NUM_THREADS];

static void *stress_worker(void *arg) {
    long id = (long)arg;
    for (int i = 0; i < ITERATIONS; i++) {
        pthread_mutex_lock(&locks[id]);
        counters[id]++;
        pthread_mutex_unlock(&locks[id]);
    }
    return NULL;
}

int main(void) {
    pthread_t threads[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_mutex_init(&locks[i], NULL);
        counters[i] = 0;
    }

    for (long i = 0; i < NUM_THREADS; i++) {
        if (pthread_create(&threads[i], NULL, stress_worker, (void *)i) != 0) {
            perror("pthread_create");
            return 1;
        }
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_mutex_destroy(&locks[i]);
    }

    return 0;
}

