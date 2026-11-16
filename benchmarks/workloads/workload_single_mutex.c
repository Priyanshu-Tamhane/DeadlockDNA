/*
 * workload_single_mutex.c — Single Thread Mutex Workload
 * DeadlockDNA — benchmarks/workloads/
 *
 * Acquires and releases a single mutex in a tight loop.
 * Evaluates event parsing and overhead under uncontended locking.
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#define ITERATIONS 500000

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static volatile long counter = 0;

int main(void) {
    for (int i = 0; i < ITERATIONS; i++) {
        pthread_mutex_lock(&lock);
        counter++;
        pthread_mutex_unlock(&lock);
    }
    return 0;
}

