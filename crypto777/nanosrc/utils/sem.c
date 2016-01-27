/*
    Copyright (c) 2013 Martin Sustrik  All rights reserved.

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

#include "sem.h"
#include "err.h"
#include "fast.h"

#if defined __APPLE__ || defined __PNACL

void nn_sem_init (struct nn_sem *myself)
{
    int rc;

    rc = pthread_mutex_init (&myself->mutex, NULL);
    errnum_assert (rc == 0, rc);
    rc = pthread_cond_init (&myself->cond, NULL);
    errnum_assert (rc == 0, rc);
    myself->signaled = 0;
}

void nn_sem_term (struct nn_sem *myself)
{
    int rc;

    rc = pthread_cond_destroy (&myself->cond);
    errnum_assert (rc == 0, rc);
    rc = pthread_mutex_destroy (&myself->mutex);
    errnum_assert (rc == 0, rc);
}

void nn_sem_post (struct nn_sem *myself)
{
    int rc;

    rc = pthread_mutex_lock (&myself->mutex);
    errnum_assert (rc == 0, rc);
    nn_assert (myself->signaled == 0);
    myself->signaled = 1;
    rc = pthread_cond_signal (&myself->cond);
    errnum_assert (rc == 0, rc);
    rc = pthread_mutex_unlock (&myself->mutex);
    errnum_assert (rc == 0, rc);
}

int nn_sem_wait (struct nn_sem *myself)
{
    int rc;

    /*  With OSX, semaphores are global named objects. They are not useful for
        our use case. To get a similar object we exploit the implementation
        detail of pthread_cond_wait() in Darwin kernel: It exits if signal is
        caught. Note that this behaviour is not mandated by POSIX
        and may break with future versions of Darwin. */
    rc = pthread_mutex_lock (&myself->mutex);
    errnum_assert (rc == 0, rc);
    if (nn_fast (myself->signaled)) {
        rc = pthread_mutex_unlock (&myself->mutex);
        errnum_assert (rc == 0, rc);
        return 0;
    }
    rc = pthread_cond_wait (&myself->cond, &myself->mutex);
    errnum_assert (rc == 0, rc);
    if (nn_slow (!myself->signaled)) {
        rc = pthread_mutex_unlock (&myself->mutex);
        errnum_assert (rc == 0, rc);
        return -EINTR;
    }
    myself->signaled = 0;
    rc = pthread_mutex_unlock (&myself->mutex);
    errnum_assert (rc == 0, rc);

    return 0;
}

#elif defined NN_HAVE_WINDOWS

void nn_sem_init (struct nn_sem *myself)
{
    myself->h = CreateEvent (NULL, FALSE, FALSE, NULL);
    win_assert (myself->h);
}

void nn_sem_term (struct nn_sem *myself)
{
    BOOL brc;

    brc = CloseHandle (myself->h);
    win_assert (brc);
}

void nn_sem_post (struct nn_sem *myself)
{
    BOOL brc;

    brc = SetEvent (myself->h);
    win_assert (brc);
}

int nn_sem_wait (struct nn_sem *myself)
{
    DWORD rc;

    rc = WaitForSingleObject (myself->h, INFINITE);
    win_assert (rc != WAIT_FAILED);
    nn_assert (rc == WAIT_OBJECT_0);

    return 0;
}

#elif defined NN_HAVE_SEMAPHORE

void nn_sem_init (struct nn_sem *myself)
{
    int rc;

    rc = sem_init (&myself->sem, 0, 0);
    errno_assert (rc == 0);
}

void nn_sem_term (struct nn_sem *myself)
{
    int rc;

    rc = sem_destroy (&myself->sem);
    errno_assert (rc == 0);
}

void nn_sem_post (struct nn_sem *myself)
{
    int rc;

    rc = sem_post (&myself->sem);
    errno_assert (rc == 0);
}

int nn_sem_wait (struct nn_sem *myself)
{
    int rc;

    rc = sem_wait (&myself->sem);
    if (nn_slow (rc < 0 && errno == EINTR))
        return -EINTR;
    errno_assert (rc == 0);
    return 0;
}

#else
#error
#endif

