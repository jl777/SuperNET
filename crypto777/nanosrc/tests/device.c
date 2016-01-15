/*
    Copyright (c) 2012 Martin Sustrik  All rights reserved.
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

#include "../nn.h"
#include "../bus.h"
#include "../pair.h"
#include "../pipeline.h"
#include "../inproc.h"

#include "testutil.h"
#include "../utils/attr.h"
#include "../utils/thread.h"

#define SOCKET_ADDRESS_A "inproc://a"
#define SOCKET_ADDRESS_B "inproc://b"
#define SOCKET_ADDRESS_C "inproc://c"
#define SOCKET_ADDRESS_D "inproc://d"
#define SOCKET_ADDRESS_E "inproc://e"

void device1 (NN_UNUSED void *arg)
{
    int rc;
    int deva;
    int devb;

    /*  Intialise the device sockets. */
    deva = test_socket (AF_SP_RAW, NN_PAIR);
    test_bind (deva, SOCKET_ADDRESS_A);
    devb = test_socket (AF_SP_RAW, NN_PAIR);
    test_bind (devb, SOCKET_ADDRESS_B);

    /*  Run the device. */
    rc = nn_device (deva, devb);
    nn_assert (rc < 0 && nn_errno () == ETERM);

    /*  Clean up. */
    test_close (devb);
    test_close (deva);
}

void device2 (NN_UNUSED void *arg)
{
    int rc;
    int devc;
    int devd;

    /*  Intialise the device sockets. */
    devc = test_socket (AF_SP_RAW, NN_PULL);
    test_bind (devc, SOCKET_ADDRESS_C);
    devd = test_socket (AF_SP_RAW, NN_PUSH);
    test_bind (devd, SOCKET_ADDRESS_D);

    /*  Run the device. */
    rc = nn_device (devc, devd);
    nn_assert (rc < 0 && nn_errno () == ETERM);

    /*  Clean up. */
    test_close (devd);
    test_close (devc);
}

void device3 (NN_UNUSED void *arg)
{
    int rc;
    int deve;

    /*  Intialise the device socket. */
    deve = test_socket (AF_SP_RAW, NN_BUS);
    test_bind (deve, SOCKET_ADDRESS_E);

    /*  Run the device. */
    rc = nn_device (deve, -1);
    nn_assert (rc < 0 && nn_errno () == ETERM);

    /*  Clean up. */
    test_close (deve);
}

int testdevice()
{
    int rc;
    int enda;
    int endb;
    int endc;
    int endd;
    int ende1;
    int ende2;
    struct nn_thread thread1;
    struct nn_thread thread2;
    struct nn_thread thread3;
    char buf [3];
    int timeo;
    printf("test device\n");

    /*  Test the bi-directional device. */

    /*  Start the device. */
    //printf("start thread\n");
    nn_thread_init (&thread1, device1, NULL);
    nn_sleep(3000);
    /*  Create two sockets to connect to the device. */
    //printf("create NN_PAIR\n");
    enda = test_socket (AF_SP, NN_PAIR);
    //printf("connect to enda.%d\n",enda);
    //nn_sleep(3000);
    test_connect (enda, SOCKET_ADDRESS_A);
    //printf("connect to endb\n");
    //nn_sleep(3000);
    endb = test_socket (AF_SP, NN_PAIR);
    //nn_sleep(3000);
    test_connect (endb, SOCKET_ADDRESS_B);
    //printf("send messages (%d %d)\n",enda,endb);
    /*  Pass a pair of messages between endpoints. */
    test_send (enda, "ABC");
    test_recv (endb, "ABC");
    test_send (endb, "ABC");
    test_recv (enda, "ABC");
    //printf("close %d/%d\n",endb,enda);
    /*  Clean up. */
    test_close (endb);
    test_close (enda);

    /*  Test the uni-directional device. */

    /*  Start the device. */
    nn_thread_init (&thread2, device2, NULL);

    /*  Create two sockets to connect to the device. */
    endc = test_socket (AF_SP, NN_PUSH);
    test_connect (endc, SOCKET_ADDRESS_C);
    endd = test_socket (AF_SP, NN_PULL);
    test_connect (endd, SOCKET_ADDRESS_D);

    /*  Pass a message between endpoints. */
    test_send (endc, "XYZ");
    test_recv (endd, "XYZ");

    /*  Clean up. */
    test_close (endd);
    test_close (endc);

    /*  Test the loopback device. */

    /*  Start the device. */
    nn_thread_init (&thread3, device3, NULL);

    /*  Create two sockets to connect to the device. */
    ende1 = test_socket (AF_SP, NN_BUS);
    test_connect (ende1, SOCKET_ADDRESS_E);
    ende2 = test_socket (AF_SP, NN_BUS);
    test_connect (ende2, SOCKET_ADDRESS_E);

    /*  BUS is unreliable so wait a bit for connections to be established. */
    nn_sleep (1000);

    /*  Pass a message to the bus. */
    test_send (ende1, "KLM");
    test_recv (ende2, "KLM");

    //  Make sure that the message doesn't arrive at the socket it was originally sent to
    timeo = 100;
    rc = nn_setsockopt (ende1, NN_SOL_SOCKET, NN_RCVTIMEO,&timeo, sizeof (timeo));
    errno_assert (rc == 0);
    rc = nn_recv (ende1, buf, sizeof (buf), 0);
    if ( nn_errno() != ETIMEDOUT )
        errno_assert (rc < 0 && nn_errno () == EAGAIN);
    //printf("closes\n");
    /*  Clean up. */
    test_close (ende2);
    test_close (ende1);

    /*  Shut down the devices. */
    //printf("nn_term\n");
    nn_term ();
    //printf("nn_thread_terms\n");
    nn_thread_term (&thread1);
    nn_thread_term (&thread2);
    nn_thread_term (&thread3);

    return 0;
}

