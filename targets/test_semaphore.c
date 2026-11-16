/*
 * test_semaphore.c — Semaphore-Based Deadlock
 * DeadlockDNA — targets/
 *
 * Two threads, two binary semaphores, deterministic deadlock via barrier.
 *
 *   T1 down(S1) → down(S2)
 *   T2 down(S2) → down(S1)
 *
 * NOTE: sem_wait() uses futex() internally — the observer captures
 * FUTEX_WAIT events at the semaphore addresses, same mechanism as mutexes.
 *
 * Compile:  gcc -pthread targets/test_semaphore.c -o targets/test_semaphore
 * Run:      ./targets/test_semaphore
 * Stop:     Ctrl+C
 */

#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <signal.h>

static sem_t             S1, S2;
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
    printf("[T1 TID=%-6d] sem_wait S1  addr=%p\n", tid, (void *)&S1); fflush(stdout);
    sem_wait(&S1);
    printf("[T1 TID=%-6d] acquired S1\n", tid); fflush(stdout);
    pthread_barrier_wait(&barrier);
    printf("[T1 TID=%-6d] sem_wait S2  addr=%p  <-- will block\n", tid, (void *)&S2); fflush(stdout);
    sem_wait(&S2);   /* DEADLOCK */
    sem_post(&S2);
    sem_post(&S1);
    return NULL;
}

static void *thread2(void *arg) {
    (void)arg;
    pid_t tid = get_tid();
    printf("[T2 TID=%-6d] sem_wait S2  addr=%p\n", tid, (void *)&S2); fflush(stdout);
    sem_wait(&S2);
    printf("[T2 TID=%-6d] acquired S2\n", tid); fflush(stdout);
    pthread_barrier_wait(&barrier);
    printf("[T2 TID=%-6d] sem_wait S1  addr=%p  <-- will block\n", tid, (void *)&S1); fflush(stdout);
    sem_wait(&S1);   /* DEADLOCK */
    sem_post(&S1);
    sem_post(&S2);
    return NULL;
}

int main(void) {
    signal(SIGINT, handle_sigint);
    printf("=== DeadlockDNA :: Semaphore Deadlock ===\n");
    printf("PID=%d\n", getpid());
    printf("S1=%p  S2=%p\n", (void *)&S1, (void *)&S2);
    printf("NOTE: sem_wait uses futex internally — observer captures futex events.\n\n");
    fflush(stdout);

    sem_init(&S1, 0, 1);    /* binary semaphore, count=1 */
    sem_init(&S2, 0, 1);
    pthread_barrier_init(&barrier, NULL, 2);

    pthread_t t1, t2;
    pthread_create(&t1, NULL, thread1, NULL);
    pthread_create(&t2, NULL, thread2, NULL);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    sem_destroy(&S1);
    sem_destroy(&S2);
    pthread_barrier_destroy(&barrier);
    return 0;
}
