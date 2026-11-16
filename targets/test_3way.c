/*
 * test_3way.c — Three-Thread Mutex Deadlock
 * DeadlockDNA — targets/
 *
 * Three threads, three mutexes, deterministic deadlock via barrier.
 *
 *   T1 acquires L1 → waits for L2
 *   T2 acquires L2 → waits for L3
 *   T3 acquires L3 → waits for L1
 *
 * RAG cycle: L1 → T1 → L2 → T2 → L3 → T3 → L1
 *
 * Compile:  gcc -pthread targets/test_3way.c -o targets/test_3way
 * Run:      ./targets/test_3way
 * Stop:     Ctrl+C
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <signal.h>

static pthread_mutex_t   L1 = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t   L2 = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t   L3 = PTHREAD_MUTEX_INITIALIZER;
static pthread_barrier_t barrier;

static pid_t get_tid(void) { return (pid_t)syscall(SYS_gettid); }

static void handle_sigint(int sig) {
    (void)sig;
    printf("\n[deadlockdna] SIGINT received — exiting.\n");
    fflush(stdout);
    exit(0);
}

static void *thread1(void *arg) {
    (void)arg;
    pid_t tid = get_tid();
    printf("[T1 TID=%-6d] acquiring L1  addr=%p\n", tid, (void *)&L1); fflush(stdout);
    pthread_mutex_lock(&L1);
    printf("[T1 TID=%-6d] acquired  L1\n", tid); fflush(stdout);
    pthread_barrier_wait(&barrier);
    printf("[T1 TID=%-6d] waiting   L2  addr=%p  <-- will block\n", tid, (void *)&L2); fflush(stdout);
    pthread_mutex_lock(&L2);   /* DEADLOCK */
    pthread_mutex_unlock(&L2);
    pthread_mutex_unlock(&L1);
    return NULL;
}

static void *thread2(void *arg) {
    (void)arg;
    pid_t tid = get_tid();
    printf("[T2 TID=%-6d] acquiring L2  addr=%p\n", tid, (void *)&L2); fflush(stdout);
    pthread_mutex_lock(&L2);
    printf("[T2 TID=%-6d] acquired  L2\n", tid); fflush(stdout);
    pthread_barrier_wait(&barrier);
    printf("[T2 TID=%-6d] waiting   L3  addr=%p  <-- will block\n", tid, (void *)&L3); fflush(stdout);
    pthread_mutex_lock(&L3);   /* DEADLOCK */
    pthread_mutex_unlock(&L3);
    pthread_mutex_unlock(&L2);
    return NULL;
}

static void *thread3(void *arg) {
    (void)arg;
    pid_t tid = get_tid();
    printf("[T3 TID=%-6d] acquiring L3  addr=%p\n", tid, (void *)&L3); fflush(stdout);
    pthread_mutex_lock(&L3);
    printf("[T3 TID=%-6d] acquired  L3\n", tid); fflush(stdout);
    pthread_barrier_wait(&barrier);
    printf("[T3 TID=%-6d] waiting   L1  addr=%p  <-- will block\n", tid, (void *)&L1); fflush(stdout);
    pthread_mutex_lock(&L1);   /* DEADLOCK */
    pthread_mutex_unlock(&L1);
    pthread_mutex_unlock(&L3);
    return NULL;
}

int main(void) {
    signal(SIGINT, handle_sigint);
    printf("=== DeadlockDNA :: 3-Way Mutex Deadlock ===\n");
    printf("PID=%d\n", getpid());
    printf("L1=%p  L2=%p  L3=%p\n\n", (void *)&L1, (void *)&L2, (void *)&L3);
    fflush(stdout);

    sleep(2);       /* Give eBPF observer 2 seconds to compile and attach */

    pthread_barrier_init(&barrier, NULL, 3);
    pthread_t t1, t2, t3;
    pthread_create(&t1, NULL, thread1, NULL);
    pthread_create(&t2, NULL, thread2, NULL);
    pthread_create(&t3, NULL, thread3, NULL);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    pthread_join(t3, NULL);
    pthread_barrier_destroy(&barrier);
    return 0;
}
