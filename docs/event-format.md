# DeadlockDNA Event Format Specification

The eBPF observer emits one JSON line per synchronization event on standard output.

## Schema

```json
{
  "timestamp_ns": 1712567890123456,
  "pid": 5000,
  "tid": 5001,
  "resource": "0x7ffd1234",
  "operation": "LOCK_REQUEST",
  "owner_tid": null
}
```

## Field Descriptions

| Field | Type | Description |
|---|---|---|
| `timestamp_ns` | `integer` | Monotonic nanoseconds since system boot (from eBPF `nsecs`) or simulated relative nanoseconds. |
| `pid` | `integer` | Process ID (TGID) of the target process. |
| `tid` | `integer` | Thread ID of the executing thread. |
| `resource` | `string` | Hex address of the synchronization primitive (mutex or semaphore). |
| `operation` | `string` | Synchronization event type (`LOCK_REQUEST`, `LOCK_ACQUIRED`, `LOCK_RELEASED`). |
| `owner_tid` | `integer` or `null` | Optional TID of current owner if inferable from futex word value. |

## Supported Operations

* `LOCK_REQUEST`: Thread entered `futex(..., FUTEX_WAIT)` waiting for a contended resource.
* `LOCK_ACQUIRED`: Thread returned successfully from `pthread_mutex_lock` or `sem_wait`.
* `LOCK_RELEASED`: Thread called `pthread_mutex_unlock` or `sem_post`.
