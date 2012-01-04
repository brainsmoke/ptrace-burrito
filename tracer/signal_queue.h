#ifndef SIGNAL_QUEUE_H
#define SIGNAL_QUEUE_H

#include <signal.h>

#include "trace.h"

/* Trivial queue datastructure to store unhandled signals
 *
 */

typedef struct signal_queue_s signal_queue_t;

signal_queue_t *add_signal_queue(trace_t *t);
void del_signal_queue(trace_t *t);
signal_queue_t *signal_queue(trace_t *t);

void enqueue_signal(signal_queue_t *q, long signal, siginfo_t *info);
int dequeue_signal(signal_queue_t *q, long *signal, siginfo_t *info);
int signal_waiting(signal_queue_t *q);

#endif /* SIGNAL_QUEUE_H */
