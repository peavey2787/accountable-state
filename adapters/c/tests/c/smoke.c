/* A real C client of gv_proofs.h: the Unreal/Godot-style native host path, built with warnings as errors. */
#include <stdio.h>
#include <string.h>

#include "gv_proofs.h"

#define CHECK(cond)                                         \
  do {                                                      \
    if (!(cond)) {                                          \
      fprintf(stderr, "FAIL: %s (line %d)\n", #cond, __LINE__); \
      return 1;                                             \
    }                                                       \
  } while (0)

int main(void) {
  GvQueue *q = NULL;
  CHECK(gv_queue_open(NULL, 0, NULL, 0, 1000, 1 << 20, &q) == GV_OK && q != NULL);

  uint8_t match[32];
  memset(match, 7, sizeof match);
  /* A pack holding one blob that is not evidence: judged Failed, never a conviction. */
  const uint8_t payload[] = {1, 0, 0, 0, 3, 0, 0, 0, 1, 2, 3};
  uint8_t job[32];
  CHECK(gv_queue_submit(q, 1, match, payload, sizeof payload, 1, UINT64_MAX, 1000, job) == GV_OK);

  uint8_t state = 255;
  CHECK(gv_queue_job_state(q, job, &state) == GV_OK && state == 0);
  size_t done = 0;
  CHECK(gv_queue_step(q, 1001, &done) == GV_OK && done == 1);
  CHECK(gv_queue_job_state(q, job, &state) == GV_OK && state == 7);

  GvBuffer writes = {0};
  CHECK(gv_queue_take_writes(q, &writes) == GV_OK && writes.len > 4);
  uint8_t *stored = writes.ptr;
  size_t stored_len = writes.len;
  gv_queue_free(q);

  GvQueue *again = NULL;
  CHECK(gv_queue_open(stored, stored_len, NULL, 0, 2000, 1 << 20, &again) == GV_OK);
  gv_buffer_free(writes);
  CHECK(gv_queue_job_state(again, job, &state) == GV_OK && state == 7);

  uint8_t unknown[32] = {0};
  CHECK(gv_queue_job_state(again, unknown, &state) == GV_NOT_FOUND);
  CHECK(gv_queue_step(NULL, 0, &done) == GV_NULL_ARGUMENT);
  gv_queue_free(again);

  puts("PASS: C client of the proof queue C ABI (open, submit, step, persist, reopen)");
  return 0;
}
