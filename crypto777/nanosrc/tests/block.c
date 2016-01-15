/*
    Copyright (c) 2012 Martin Sustrik  All rights reserved.

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

#include "../nn.h"
#include "../pair.h"

#include "testutil.h"
#include "../utils/attr.h"
#include "../utils/thread.h"

/*  This test checks whether blocking on send/recv works as expected. */

#define SOCKET_ADDRESS "inproc://a"

static int sc;
static int sb;

void worker (NN_UNUSED void *arg)
{
    /*  Wait 0.1 sec for the main thread to block. */
    nn_sleep (100);

    test_send (sc, "ABC");

    /*  Wait 0.1 sec for the main thread to process the previous message
        and block once again. */
    nn_sleep (100);

    test_send (sc, "ABC");
}

int testblock()
{
    struct nn_thread thread;
    printf("test block\n");

    sb = test_socket (AF_SP, NN_PAIR);
    test_bind (sb, SOCKET_ADDRESS);
    sc = test_socket (AF_SP, NN_PAIR);
    test_connect (sc, SOCKET_ADDRESS);

    nn_thread_init (&thread, worker, NULL);

    test_recv (sb, "ABC");
    test_recv (sb, "ABC");

    nn_thread_term (&thread);

    test_close (sc);
    test_close (sb);
    //printf("finished block test\n");
    return 0;
}

