/*
    Copyright (c) 2012-2013 Martin Sustrik  All rights reserved.

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

#include "err.h"
#include "int.h"
#include "closefd.h"

#include <sys/eventfd.h>
#include <unistd.h>
#include <fcntl.h>

int nn_efd_init(struct nn_efd *self)
{
    int rc;
    int flags;
    //PostMessage("inside efd_init eventfd\n");
    self->efd = eventfd(0, EFD_CLOEXEC);
    //PostMessage("self->efd: %d\n",self->efd);
    if (self->efd == -1 && (errno == EMFILE || errno == ENFILE))
        return -EMFILE;
    errno_assert(self->efd != -1);
    flags = fcntl(self->efd,F_GETFL,0);
    //PostMessage("fcntl flags: %d\n",flags);
    if ( flags == -1 )
        flags = 0;
    rc = fcntl(self->efd, F_SETFL, flags | O_NONBLOCK);
    //PostMessage("fcntl rc: %d\n",rc);
    errno_assert (rc != -1);
    return 0;
}

void nn_efd_term (struct nn_efd *self)
{
    nn_closefd (self->efd);
}

nn_fd nn_efd_getfd (struct nn_efd *self)
{
    return self->efd;
}

void nn_efd_signal (struct nn_efd *self)
{
    const uint64_t one = 1;
    ssize_t nbytes;

    nbytes = write (self->efd, &one, sizeof (one));
    errno_assert (nbytes == sizeof (one));
}

void nn_efd_unsignal (struct nn_efd *self)
{
    uint64_t count;

    /*  Extract all the signals from the eventfd. */
    ssize_t sz = read (self->efd, &count, sizeof (count));
    errno_assert (sz >= 0);
    nn_assert (sz == sizeof (count));
}

