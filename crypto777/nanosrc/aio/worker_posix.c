/*
    Copyright (c) 2013-2014 Martin Sustrik  All rights reserved.
    Copyright (c) 2013 GoPivotal, Inc.  All rights reserved.

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom
    the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included
    in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
    IN THE SOFTWARE.
*/

#include "ctx.h"

#include "../utils/err.h"
#include "../utils/fast.h"
#include "../utils/cont.h"
#include "../utils/attr.h"
#include "../utils/queue.h"

/*  Private functions. */
static void nn_worker_routine (void *arg);

void nn_worker_fd_init (struct nn_worker_fd *self, int src,
    struct nn_fsm *owner)
{
    self->src = src;
    self->owner = owner;
}

void nn_worker_fd_term (NN_UNUSED struct nn_worker_fd *self)
{
}

void nn_worker_add_fd (struct nn_worker *self, int s, struct nn_worker_fd *fd)
{
    nn_poller_add (&((struct nn_worker*) self)->poller, s, &fd->hndl);
}

void nn_worker_rm_fd (struct nn_worker *self, struct nn_worker_fd *fd)
{
    nn_poller_rm (&((struct nn_worker*) self)->poller, &fd->hndl);
}

void nn_worker_set_in (struct nn_worker *self, struct nn_worker_fd *fd)
{
    nn_poller_set_in (&((struct nn_worker*) self)->poller, &fd->hndl);
}

void nn_worker_reset_in (struct nn_worker *self, struct nn_worker_fd *fd)
{
    nn_poller_reset_in (&((struct nn_worker*) self)->poller, &fd->hndl);
}

void nn_worker_set_out (struct nn_worker *self, struct nn_worker_fd *fd)
{
    nn_poller_set_out (&((struct nn_worker*) self)->poller, &fd->hndl);
}

void nn_worker_reset_out (struct nn_worker *self, struct nn_worker_fd *fd)
{
    nn_poller_reset_out (&((struct nn_worker*) self)->poller, &fd->hndl);
}

void nn_worker_add_timer (struct nn_worker *self, int timeout,
    struct nn_worker_timer *timer)
{
    nn_timerset_add (&((struct nn_worker*) self)->timerset, timeout,
        &timer->hndl);
}

void nn_worker_rm_timer (struct nn_worker *self, struct nn_worker_timer *timer)
{
    nn_timerset_rm (&((struct nn_worker*) self)->timerset, &timer->hndl);
}

void nn_worker_task_init (struct nn_worker_task *self, int src,
    struct nn_fsm *owner)
{
    self->src = src;
    self->owner = owner;
    nn_queue_item_init(&self->item);
}

void nn_worker_task_term (struct nn_worker_task *self)
{
    nn_queue_item_term (&self->item);
}

#include <unistd.h>
int nn_worker_init(struct nn_worker *self)
{
    int32_t rc;
    PNACL_message("nn_worker_init %p\n",self);
    sleep(1);
    rc = nn_efd_init(&self->efd);
    PNACL_message("efd init: rc.%d\n",rc);
    if ( rc < 0 )
        return rc;
    PNACL_message("nn_mutex_init\n");
    nn_mutex_init(&self->sync);
    PNACL_message("nn_queue_init\n");
    nn_queue_init(&self->tasks);
    PNACL_message("nn_queue_item_init\n");
    nn_queue_item_init(&self->stop);
    PNACL_message("nn_poller_init\n");
    nn_poller_init(&self->poller);
    PNACL_message("nn_poller_add\n");
    nn_poller_add(&self->poller,nn_efd_getfd(&self->efd),&self->efd_hndl);
    PNACL_message("nn_poller_set_in\n");
    nn_poller_set_in(&self->poller, &self->efd_hndl);
    PNACL_message("nn_timerset_init\n");
    nn_timerset_init(&self->timerset);
    PNACL_message("nn_thread_init\n");
    nn_thread_init(&self->thread,nn_worker_routine, self);
    PNACL_message("finished nn_worker_init\n");
    return 0;
}

void nn_worker_term (struct nn_worker *self)
{
    /*  Ask worker thread to terminate. */
    nn_mutex_lock (&self->sync);
    nn_queue_push (&self->tasks, &self->stop);
    nn_efd_signal (&self->efd);
    nn_mutex_unlock (&self->sync);

    /*  Wait till worker thread terminates. */
    nn_thread_term (&self->thread);

    /*  Clean up. */
    nn_timerset_term (&self->timerset);
    nn_poller_term (&self->poller);
    nn_efd_term (&self->efd);
    nn_queue_item_term (&self->stop);
    nn_queue_term (&self->tasks);
    nn_mutex_term (&self->sync);
}

void nn_worker_execute (struct nn_worker *self, struct nn_worker_task *task)
{
    nn_mutex_lock (&self->sync);
    nn_queue_push (&self->tasks, &task->item);
    nn_efd_signal (&self->efd);
    nn_mutex_unlock (&self->sync);
}

void nn_worker_cancel (struct nn_worker *self, struct nn_worker_task *task)
{
    nn_mutex_lock (&self->sync);
    nn_queue_remove (&self->tasks, &task->item);
    nn_mutex_unlock (&self->sync);
}

static void nn_worker_routine (void *arg)
{
    int32_t rc,pevent;
    struct nn_worker *self;
    struct nn_poller_hndl *phndl;
    struct nn_timerset_hndl *thndl;
    struct nn_queue tasks;
    struct nn_queue_item *item;
    struct nn_worker_task *task;
    struct nn_worker_fd *fd;
    struct nn_worker_timer *timer;
    PNACL_message("nn_worker_routine started\n");
    self = (struct nn_worker*) arg;
    while ( 1 ) //  Infinite loop. It will be interrupted only when the object is shut down.
    {
        // Wait for new events and/or timeouts.
        rc = nn_poller_wait(&self->poller,nn_timerset_timeout (&self->timerset));
        errnum_assert(rc == 0, -rc);
        while ( 1 ) // Process all expired timers
        {
            rc = nn_timerset_event(&self->timerset, &thndl);
            if ( rc == -EAGAIN )
                break;
            PNACL_message("nn_worker process expired user\n");
            errnum_assert(rc == 0, -rc);
            timer = nn_cont(thndl, struct nn_worker_timer, hndl);
            nn_ctx_enter(timer->owner->ctx);
            nn_fsm_feed(timer->owner,-1,NN_WORKER_TIMER_TIMEOUT,timer);
            nn_ctx_leave(timer->owner->ctx);
        }
        while ( 1 ) // Process all events from the poller
        {
            rc = nn_poller_event(&self->poller,&pevent,&phndl); //  Get next poller event, such as IN or OUT
            if ( nn_slow(rc == -EAGAIN) )
                break;
            PNACL_message("nn_worker process all events from the poller\n");
            if ( phndl == &self->efd_hndl ) // If there are any new incoming worker tasks, process them
            {
                nn_assert (pevent == NN_POLLER_IN);
                //  Make a local copy of the task queue. This way the application threads are not blocked and can post new tasks while the existing tasks are being processed. Also, new tasks can be posted from within task handlers
                nn_mutex_lock(&self->sync);
                nn_efd_unsignal(&self->efd);
                memcpy(&tasks,&self->tasks,sizeof(tasks));
                nn_queue_init(&self->tasks);
                nn_mutex_unlock(&self->sync);
                while ( 1 )
                {
                    item = nn_queue_pop(&tasks); //  Next worker task
                    if ( nn_slow(!item) )
                        break;
                    PNACL_message("nn_worker next worker task\n");
                    if ( nn_slow(item == &self->stop) ) //  If the worker thread is asked to stop, do so
                    {
                        nn_queue_term(&tasks);
                        return;
                    }
                    // It's a user-defined task. Notify the user that it has arrived in the worker thread
                    PNACL_message("nn_worker user defined task\n");
                    task = nn_cont(item,struct nn_worker_task,item);
                    nn_ctx_enter(task->owner->ctx);
                    nn_fsm_feed(task->owner,task->src,NN_WORKER_TASK_EXECUTE,task);
                    nn_ctx_leave (task->owner->ctx);
                }
                nn_queue_term (&tasks);
                continue;
            }
            PNACL_message("nn_worker true i/o, invoke handler\n");
            fd = nn_cont(phndl,struct nn_worker_fd,hndl); // It's a true I/O event. Invoke the handler
            PNACL_message("nn_worker true i/o, fd.%p\n",fd);
            nn_ctx_enter(fd->owner->ctx);
            PNACL_message("nn_worker true i/o, after nn_ctx_enter\n");
            nn_fsm_feed(fd->owner,fd->src,pevent,fd);
            PNACL_message("nn_worker true i/o, after nn_fsm_feed leave.%p\n",fd->owner->ctx);
            nn_ctx_leave(fd->owner->ctx);
            PNACL_message("nn_worker true i/o, after nn_ctx_leave\n");
        }
    }
}

