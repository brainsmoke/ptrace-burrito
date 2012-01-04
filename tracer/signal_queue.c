
#include <stdlib.h>

#include "trace.h"
#include "util.h"
#include "dataset.h"
#include "errors.h"
#include "signal_queue.h"

typedef struct sigq_ll_s sigq_ll_t;
struct sigq_ll_s
{
	sigq_ll_t *next;
	long signal;
	siginfo_t info;
};

struct signal_queue_s
{
	sigq_ll_t *first;
};

static int SIGNAL_QUEUE = -1;

signal_queue_t *add_signal_queue(trace_t *t)
{
	if ( SIGNAL_QUEUE == -1 )
		SIGNAL_QUEUE = register_type(sizeof(signal_queue_t));

	signal_queue_t *q = add_data((dataset_t*)&t->data, SIGNAL_QUEUE);
	*q = (signal_queue_t){ .first = NULL };

	return q;
}

void del_signal_queue(trace_t *t)
{
	long signo;
	siginfo_t info;
	signal_queue_t *q = signal_queue(t);
	while ( dequeue_signal(q, &signo, &info) );
	del_data((dataset_t*)&t->data, SIGNAL_QUEUE);
}

signal_queue_t *signal_queue(trace_t *t)
{
	return (signal_queue_t *)get_data((dataset_t*)&t->data, SIGNAL_QUEUE);
}

void enqueue_signal(signal_queue_t *q, long signo, siginfo_t *info)
{
	sigq_ll_t *i, *n;
	n = (sigq_ll_t*)try_malloc(sizeof(sigq_ll_t));
	*n = (sigq_ll_t){ .signal = signo, .info = *info };

	if (!q->first)
	{
		q->first = n;
	}
	else
	{
		for (i=q->first; i->next; i=i->next);

		i->next = n;
	}
}

int dequeue_signal(signal_queue_t *q, long *signo, siginfo_t *info)
{
	sigq_ll_t *i = q->first;
	if (!i)
		return 0;

	q->first = i->next;

	*signo = i->signal;
	*info = i->info;
	free(i);
	return 1;
}

int signal_waiting(signal_queue_t *q)
{
	return q->first != 0;
}

