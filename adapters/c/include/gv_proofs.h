/* C ABI for the accountable-state proof queue. A handle is used from one thread at a time;
 * gv_last_error is per thread. Every call returns a GvStatus. The host owns storage: persist the
 * blobs from gv_queue_take_writes (in order) before acknowledging anything, and pass them back to
 * gv_queue_open after a restart. */
#ifndef GV_PROOFS_H
#define GV_PROOFS_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef enum GvStatus {
  GV_OK = 0,
  GV_NULL_ARGUMENT = 1,
  GV_INVALID = 2,   /* rejected input; see gv_last_error */
  GV_NOT_FOUND = 3, /* no such job */
  GV_PANICKED = 4   /* contained internal fault; discard the handle */
} GvStatus;

typedef struct GvQueue GvQueue;

typedef struct GvBuffer {
  uint8_t *ptr;
  size_t len;
  size_t cap;
} GvBuffer;

/* stored: a pack (u32 count, then u32 length + bytes per blob, little-endian) of earlier
 * gv_queue_take_writes results, or empty. witnesses: pinned 32-byte ids, concatenated, or empty. */
GvStatus gv_queue_open(const uint8_t *stored, size_t stored_len, const uint8_t *witnesses,
                       size_t witnesses_len, uint64_t now, uint64_t outbox_limit,
                       GvQueue **out);
void gv_queue_free(GvQueue *q);

/* priority: 0 high, 1 normal, 2 low. deadline: absolute time or UINT64_MAX for none.
 * match_id: 32 bytes. job_out: 32 bytes. */
GvStatus gv_queue_submit(const GvQueue *q, uint16_t family, const uint8_t *match_id,
                         const uint8_t *payload, size_t payload_len, uint8_t priority,
                         uint64_t deadline, uint64_t now, uint8_t *job_out);
GvStatus gv_queue_step(const GvQueue *q, uint64_t now, size_t *done);
GvStatus gv_queue_job_state(const GvQueue *q, const uint8_t *job, uint8_t *state);
GvStatus gv_queue_match_status(const GvQueue *q, const uint8_t *match_id,
                               const uint8_t *required, size_t required_len, GvBuffer *out);
GvStatus gv_queue_events_after(const GvQueue *q, uint64_t cursor, size_t limit, GvBuffer *out);
GvStatus gv_queue_take_writes(const GvQueue *q, GvBuffer *out);
GvStatus gv_last_error(GvBuffer *out);
void gv_buffer_free(GvBuffer buf);

#ifdef __cplusplus
}
#endif
#endif
