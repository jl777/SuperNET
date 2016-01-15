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
#include "../pubsub.h"
#include "../pipeline.h"
#include "../ipc.h"

#include "testutil.h"
#include "../utils/thread.h"
#include "../utils/atomic.h"
#include "../utils/atomic.h"

/*  Stress test the IPC transport. */

#define THREAD_COUNT 12
#define TEST_LOOPS 10
#define SOCKET_ADDRESS "ipc://test-stress.ipc"

static struct nn_atomic active;

void server(NN_UNUSED void *arg)
{
    struct nn_thread *self = arg;
    int bytes;
    int sock = nn_socket(AF_SP, NN_PULL);
    nn_assert(sock >= 0);
    nn_assert(nn_bind(sock, SOCKET_ADDRESS) >= 0);
    //printf("self.%p routine.%p vs %p server sock.%d\n",self,self->routine,server,sock);
    while ( self->routine == server )
    {
        char *buf = NULL;
        if (!active.n) break;
        bytes = nn_recv(sock, &buf, NN_MSG, 0);
        nn_assert(bytes >= 0);
        nn_freemsg(buf);
    }
    nn_close(sock);
}

void client(void *arg)
{
    struct nn_thread *self = arg;
    int32_t i,val,bytes; char msg[] = "0"; int sz_msg = (int32_t)strlen (msg) + 1; // '\0' too
    //printf("self.%p routine.%p vs %p\n",self,self->routine,client);
    
    for (i = 0; i < TEST_LOOPS; i++)
    {
        int cli_sock = nn_socket(AF_SP, NN_PUSH);
        if ( cli_sock >= 0 )
        {
            //printf("client i.%d cli_sock.%d\n",i,cli_sock);
            nn_assert(cli_sock >= 0);
            val = nn_connect(cli_sock, SOCKET_ADDRESS);
            //printf("client i.%d connect.%d\n",i,val);
            nn_assert(val >= 0);
            bytes = nn_send(cli_sock, msg, sz_msg, 0);
            //printf("bytes sent.%d vs %d\n",bytes,sz_msg);
            nn_assert(bytes == sz_msg);
            test_close(cli_sock);
            if ( self->routine != client )
            {
                printf("termination detected\n");
                break;
            }
        }
        else printf("error getting nn_socket i.%d\n",i);
    }
    nn_atomic_dec(&active, 1);
}

int testipc_stress()
{
#if 1
    int i;
	int cli_sock;
	int bytes;
    struct nn_thread srv_thread;
    struct nn_thread cli_threads[THREAD_COUNT];
    //printf("test ipc stress\n");
    nn_atomic_init(&active,THREAD_COUNT);
    // Stress the shutdown algorithm
    nn_thread_init(&srv_thread, server,&srv_thread);
    if ( 1 )
    {
        for (i = 0; i != THREAD_COUNT; ++i)
            nn_thread_init(&cli_threads[i], client,&cli_threads[i]);
        for (i = 0; i != THREAD_COUNT; ++i)
            nn_thread_term(&cli_threads[i]);
    }
    active.n = 0;
    nn_sleep(1000);
    cli_sock = test_socket(AF_SP, NN_PUSH);
    //printf("main cli_sock.%d\n",cli_sock);
    nn_assert(cli_sock >= 0);
    nn_assert(nn_connect(cli_sock, SOCKET_ADDRESS) >= 0);
    bytes = nn_send(cli_sock, &i, sizeof(i), 0);
    //printf("main bytes.%d vs %d\n",bytes,(int32_t)sizeof(i));
    nn_assert(bytes == sizeof(i));
    //printf("close sock.%d\n",cli_sock);
    nn_close(cli_sock);
    nn_thread_term(&srv_thread);
#endif 
    //printf("finished ipc stress\n");

    return 0;
}

