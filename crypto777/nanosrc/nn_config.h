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

#ifndef NNCONFIG_H_INCLUDED
#define NNCONFIG_H_INCLUDED

#ifdef __APPLE__
#define NN_HAVE_OSX 1
#endif

#define NN_HAVE_POLL 1 // must have
#define NN_HAVE_SEMAPHORE 1 // must have

// need one of following 3, listed in order of precedence, used by efd*
//#define NN_HAVE_EVENTFD 1
#define NN_HAVE_PIPE 1
//#define NN_HAVE_SOCKETPAIR 1

// need one of following 3, listed in order of precedence, used by poller*
#define NN_USE_POLL 1
//#define NN_USE_EPOLL 1
//#define NN_USE_KQUEUE 1

#define NN_DISABLE_GETADDRINFO_A 1
#define NN_USE_LITERAL_IFADDR 1
#define NN_HAVE_STDINT 1

#define NN_HAVE_MSG_CONTROL 1
//#define STANDALONE 1

#ifdef __PNACL
//#define FD_CLOEXEC 1

void PNACL_message(const char* format, ...);
#include <glibc-compat/sys/uio.h>
#include <glibc-compat/sys/un.h>
#else
//#define NN_ENABLE_EXTRA 1
#define PNACL_message printf
#include <sys/uio.h>
#include <sys/un.h>
#endif

/*  Size of the buffer used for batch-reads of inbound data. To keep the
 performance optimal make sure that this value is larger than network MTU. */
#define NN_USOCK_BATCH_SIZE (2048)
//#define NN_USOCK_BATCH_SIZE (_NN_USOCK_BATCH_SIZE - 5 - 256 - 16) // adjust for veclen/clen + sizeof(ctrl)
#define NN_USE_MYMSG 1

#if defined __PNACL || defined __APPLE__
#define NN_USE_MYMSG 1
#endif

#define nn_errstr() nn_strerror(nn_errno())

#endif

