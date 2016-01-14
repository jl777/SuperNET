/*
    Copyright (c) 2012-2014 Martin Sustrik  All rights reserved.
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
#include "../transport.h"
#include "../protocol.h"

#include "global.h"
#include "sock.h"
#include "ep.h"

#include "../aio/pool.h"
#include "../aio/timer.h"

#include "../utils/err.h"
#include "../utils/alloc.h"
#include "../utils/mutex.h"
#include "../utils/list.h"
#include "../utils/cont.h"
#include "../utils/random.h"
#include "../utils/glock.h"
#include "../utils/chunk.h"
#include "../utils/msg.h"
#include "../utils/attr.h"

#include "../transports/inproc/inproc.h"
#include "../transports/ipc/ipc.h"
#include "../transports/tcp/tcp.h"
#include "../transports/ws/ws.h"
#include "../transports/tcpmux/tcpmux.h"

#include "../protocols/pair/pair.h"
#include "../protocols/pair/xpair.h"
#include "../protocols/pubsub/pub.h"
#include "../protocols/pubsub/sub.h"
#include "../protocols/pubsub/xpub.h"
#include "../protocols/pubsub/xsub.h"
#include "../protocols/reqrep/rep.h"
#include "../protocols/reqrep/req.h"
#include "../protocols/reqrep/xrep.h"
#include "../protocols/reqrep/xreq.h"
#include "../protocols/pipeline/push.h"
#include "../protocols/pipeline/pull.h"
#include "../protocols/pipeline/xpush.h"
#include "../protocols/pipeline/xpull.h"
#include "../protocols/survey/respondent.h"
#include "../protocols/survey/surveyor.h"
#include "../protocols/survey/xrespondent.h"
#include "../protocols/survey/xsurveyor.h"
#include "../protocols/bus/bus.h"
#include "../protocols/bus/xbus.h"

#include "../pubsub.h"
#include "../pipeline.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined NN_HAVE_MINGW
#include <pthread.h>
#elif defined NN_HAVE_WINDOWS
#define gmtime_r(ptr_numtime, ptr_strtime) gmtime_s(ptr_strtime, ptr_numtime)
#endif
#define NN_HAVE_GMTIME_R


#if defined NN_HAVE_WINDOWS
#include "../utils/win.h"
#else
#include <unistd.h>
#endif

/*  Max number of concurrent SP sockets. */
#define NN_MAX_SOCKETS 512

/*  To save some space, list of unused socket slots uses uint16_t integers to
    refer to individual sockets. If there's a need to more that 0x10000 sockets,
    the type should be changed to uint32_t or int. */
CT_ASSERT (NN_MAX_SOCKETS <= 0x10000);

/*  This check is performed at the beginning of each socket operation to make
    sure that the library was initialised, the socket actually exists, and is
    a valid socket index. */
#define NN_BASIC_CHECKS \
    if (nn_slow (s < 0 || s > NN_MAX_SOCKETS)) {\
        errno = EBADF;\
        return -1;\
        }\
    if (nn_slow (!SELF.socks || !SELF.socks [s])) {\
        errno = EBADF;\
        return -1;\
    }

#define NN_CTX_FLAG_ZOMBIE 1

#define NN_GLOBAL_SRC_STAT_TIMER 1

#define NN_GLOBAL_STATE_IDLE           1
#define NN_GLOBAL_STATE_ACTIVE         2
#define NN_GLOBAL_STATE_STOPPING_TIMER 3

struct nn_global {

    /*  The global table of existing sockets. The descriptor representing
        the socket is the index to this table. This pointer is also used to
        find out whether context is initialised. If it is NULL, context is
        uninitialised. */
    struct nn_sock **socks;

    /*  Stack of unused file descriptors. */
    uint16_t *unused;

    /*  Number of actual open sockets in the socket table. */
    size_t nsocks;

    /*  Combination of the flags listed above. */
    int flags;

    /*  List of all available transports. */
    struct nn_list transports;

    /*  List of all available socket types. */
    struct nn_list socktypes;

    /*  Pool of worker threads. */
    struct nn_pool pool;

    /*  Timer and other machinery for submitting statistics  */
    struct nn_ctx ctx;
    struct nn_fsm fsm;
    int state;
    struct nn_timer stat_timer;

    int print_errors;
    int print_statistics;

    /*  Special socket ids  */
    int statistics_socket;

    /*  Application name for statistics  */
    char hostname[64];
    char appname[64];
};

/*  Singleton object containing the global state of the library. */
static struct nn_global SELF = {0};

/*  Context creation- and termination-related private functions. */
void nn_global_init(void);
static void nn_global_term(void);

/*  Transport-related private functions. */
static void nn_global_add_transport(struct nn_transport *transport);
static void nn_global_add_socktype(struct nn_socktype *socktype);

/*  Private function that unifies nn_bind and nn_connect functionality.
    It returns the ID of the newly created endpoint. */
static int nn_global_create_ep(int32_t s,const char *addr,int32_t bind);

/*  Private socket creator which doesn't initialize global state and
    does no locking by itself */
static int nn_global_create_socket(int32_t domain,int32_t protocol);

/*  FSM callbacks  */
static void nn_global_handler (struct nn_fsm *self,int32_t src,int32_t type,void *srcptr);
static void nn_global_shutdown (struct nn_fsm *self,int32_t src,int32_t type,void *srcptr);


int32_t nn_errno(void) { return nn_err_errno(); }

const char *nn_strerror(int32_t errnum) { return nn_err_strerror(errnum); }

void nn_global_init (void)
{
    int32_t i,rc; char *envvar,*addr;
    if ( SELF.socks != 0 ) // Check whether the library was already initialised. If so, do nothing
        return;
#if defined NN_HAVE_WINDOWS
    WSADATA data;
    /*  On Windows, initialise the socket library. */
    rc = WSAStartup (MAKEWORD (2, 2), &data);
    nn_assert (rc == 0);
    nn_assert (LOBYTE (data.wVersion) == 2 &&
        HIBYTE (data.wVersion) == 2);
#endif
    nn_alloc_init(); // Initialise the memory allocation subsystem
    nn_random_seed(); // Seed the pseudo-random number generator
    //  Allocate the global table of SP sockets. 
    SELF.socks = nn_alloc((sizeof (struct nn_sock*) * NN_MAX_SOCKETS) + (sizeof (uint16_t) * NN_MAX_SOCKETS), "socket table");
    alloc_assert (SELF.socks);
    for (i=0; i<NN_MAX_SOCKETS; i++)
        SELF.socks[i] = NULL;
    SELF.nsocks = SELF.flags = 0;
    //PNACL_message("do getenv\n");
    envvar = getenv("NN_PRINT_ERRORS"); // Print connection and accepting errors to the stderr
    SELF.print_errors = envvar && *envvar; // any non-empty string is true
    envvar = getenv("NN_PRINT_STATISTICS"); // Print socket statistics to stderr
    SELF.print_statistics = envvar && *envvar;
    SELF.unused = (uint16_t *)(SELF.socks + NN_MAX_SOCKETS); // Allocate the stack of unused file descriptors
    alloc_assert (SELF.unused);
    for (i=0; i<NN_MAX_SOCKETS; i++)
        SELF.unused [i] = NN_MAX_SOCKETS - i - 1;
    //PNACL_message("list init\n");
    // Initialise other parts of the global state.
    nn_list_init(&SELF.transports);
    nn_list_init(&SELF.socktypes);
    //PNACL_message("transports init\n");
    //  Plug in individual transports.
    //nn_global_add_transport(nn_ipc);
    nn_global_add_transport(nn_tcp);
    //nn_global_add_transport(nn_inproc);
    //nn_global_add_transport(nn_ws);
    //nn_global_add_transport(nn_tcpmux);
    //PNACL_message("socktypes init\n");
    // Plug in individual socktypes
    nn_global_add_socktype(nn_pair_socktype);
    nn_global_add_socktype(nn_xpair_socktype);
    nn_global_add_socktype(nn_rep_socktype);
    nn_global_add_socktype(nn_req_socktype);
    nn_global_add_socktype(nn_xrep_socktype);
    nn_global_add_socktype(nn_xreq_socktype);
    //nn_global_add_socktype(nn_respondent_socktype);
    //nn_global_add_socktype(nn_surveyor_socktype);
    //nn_global_add_socktype(nn_xrespondent_socktype);
    //nn_global_add_socktype(nn_xsurveyor_socktype);
    nn_global_add_socktype(nn_pub_socktype);
    nn_global_add_socktype(nn_sub_socktype);
    nn_global_add_socktype(nn_xpub_socktype);
    nn_global_add_socktype(nn_xsub_socktype);
    //nn_global_add_socktype(nn_push_socktype);
    //nn_global_add_socktype(nn_xpush_socktype);
    //nn_global_add_socktype(nn_pull_socktype);
    //nn_global_add_socktype(nn_xpull_socktype);
    //nn_global_add_socktype(nn_bus_socktype);
    //nn_global_add_socktype(nn_xbus_socktype);
    //PNACL_message("do pool init\n");
    nn_pool_init(&SELF.pool); // Start the worker threads
    //PNACL_message("do FSM init\n");
    nn_fsm_init_root(&SELF.fsm,nn_global_handler,nn_global_shutdown,&SELF.ctx); // Start FSM
    SELF.state = NN_GLOBAL_STATE_IDLE;
    //PNACL_message("ctx init\n");
    nn_ctx_init(&SELF.ctx, nn_global_getpool(),NULL);
    //PNACL_message("timer init\n");
    nn_timer_init(&SELF.stat_timer,NN_GLOBAL_SRC_STAT_TIMER,&SELF.fsm);
    //PNACL_message("do FSM start\n");
    nn_fsm_start(&SELF.fsm);
    //PNACL_message("special sockets init\n");
    //  Initializing special sockets.
    addr = getenv("NN_STATISTICS_SOCKET");
    if ( addr != 0 )
    {
        SELF.statistics_socket = nn_global_create_socket(AF_SP,NN_PUB);
        errno_assert (SELF.statistics_socket >= 0);
        rc = nn_global_create_ep(SELF.statistics_socket, addr, 0);
        errno_assert (rc >= 0);
    } else SELF.statistics_socket = -1;
    addr = getenv("NN_APPLICATION_NAME");
    if ( addr != 0 )
        strncpy (SELF.appname, addr, 63), SELF.appname[63] = '\0';
    else
    {
    //  No cross-platform way to find out application binary. Also, MSVC suggests using _getpid() instead of getpid(), however, it's not clear whether the former is supported by older versions of Windows/MSVC.
#if defined _MSC_VER
#pragma warning (push)
#pragma warning (disable:4996)
#endif
        sprintf(SELF.appname,"nanomsg.%d",getpid());
#if defined _MSC_VER
#pragma warning (pop)
#endif
    }
    addr = getenv("NN_HOSTNAME");
    if ( addr != 0 )
        strncpy (SELF.hostname,addr,63), SELF.hostname[63] = '\0';
    else
    {
        rc = gethostname(SELF.hostname,63);
        errno_assert (rc == 0);
        SELF.hostname[63] = '\0';
    }
}

static void nn_global_term (void)
{
#if defined NN_HAVE_WINDOWS
    int rc;
#endif
    struct nn_list_item *it;
    struct nn_transport *tp;

    /*  If there are no sockets remaining, uninitialise the global context. */
    nn_assert (SELF.socks);
    if (SELF.nsocks > 0)
        return;

    /*  Stop the FSM  */
    nn_ctx_enter (&SELF.ctx);
    nn_fsm_stop (&SELF.fsm);
    nn_ctx_leave (&SELF.ctx);

    /*  Shut down the worker threads. */
    nn_pool_term (&SELF.pool);

    /* Terminate ctx mutex */
    nn_ctx_term (&SELF.ctx);

    /*  Ask all the transport to deallocate their global resources. */
    while (!nn_list_empty (&SELF.transports)) {
        it = nn_list_begin (&SELF.transports);
        tp = nn_cont (it, struct nn_transport, item);
        if (tp->term)
            tp->term ();
        nn_list_erase (&SELF.transports, it);
    }

    /*  For now there's nothing to deallocate about socket types, however,
        let's remove them from the list anyway. */
    while (!nn_list_empty (&SELF.socktypes))
        nn_list_erase (&SELF.socktypes, nn_list_begin (&SELF.socktypes));

    /*  Final deallocation of the nn_global object itSELF. */
    nn_list_term (&SELF.socktypes);
    nn_list_term (&SELF.transports);
    nn_free (SELF.socks);

    /*  This marks the global state as uninitialised. */
    SELF.socks = NULL;

    /*  Shut down the memory allocation subsystem. */
    nn_alloc_term ();

    /*  On Windows, uninitialise the socket library. */
#if defined NN_HAVE_WINDOWS
    rc = WSACleanup ();
    nn_assert (rc == 0);
#endif
}

void nn_term (void)
{
    int i;

    nn_glock_lock ();

    /*  Switch the global state into the zombie state. */
    SELF.flags |= NN_CTX_FLAG_ZOMBIE;

    /*  Mark all open sockets as terminating. */
    if (SELF.socks && SELF.nsocks) {
        for (i = 0; i != NN_MAX_SOCKETS; ++i)
            if (SELF.socks [i])
                nn_sock_zombify (SELF.socks [i]);
    }

    nn_glock_unlock ();
}

void *nn_allocmsg (size_t size, int type)
{
    int rc;
    void *result;

    rc = nn_chunk_alloc (size, type, &result);
    if (rc == 0)
        return result;
    errno = -rc;
    return NULL;
}

void *nn_reallocmsg (void *msg, size_t size)
{
    int rc;

    rc = nn_chunk_realloc (size, &msg);
    if (rc == 0)
        return msg;
    errno = -rc;
    return NULL;
}

int nn_freemsg (void *msg)
{
    nn_chunk_free (msg);
    return 0;
}

struct nn_cmsghdr *nn_cmsg_nxthdr_ (const struct nn_msghdr *mhdr,
    const struct nn_cmsghdr *cmsg)
{
    char *data;
    size_t sz;
    struct nn_cmsghdr *next;
    size_t headsz;

    /*  Early return if no message is provided. */
    if (nn_slow (mhdr == NULL))
        return NULL;

    /*  Get the actual data. */
    if (mhdr->msg_controllen == NN_MSG) {
        data = *((void**) mhdr->msg_control);
        sz = nn_chunk_size (data);
    }
    else {
        data = (char*) mhdr->msg_control;
        sz = mhdr->msg_controllen;
    }

    /*  Ancillary data allocation was not even large enough for one element. */
    if (nn_slow (sz < NN_CMSG_SPACE (0)))
        return NULL;

    /*  If cmsg is set to NULL we are going to return first property.
        Otherwise move to the next property. */
    if (!cmsg)
        next = (struct nn_cmsghdr*) data;
    else
        next = (struct nn_cmsghdr*)
            (((char*) cmsg) + NN_CMSG_ALIGN_ (cmsg->cmsg_len));

    /*  If there's no space for next property, treat it as the end
        of the property list. */
    headsz = ((char*) next) - data;
    if (headsz + NN_CMSG_SPACE (0) > sz ||
          headsz + NN_CMSG_ALIGN_ (next->cmsg_len) > sz)
        return NULL;
    
    /*  Success. */
    return next;
}

int32_t nn_global_create_socket(int32_t domain,int32_t protocol)
{
    int32_t rc,s; struct nn_list_item *it; struct nn_socktype *socktype; struct nn_sock *sock;
    // The function is called with nn_glock held
    if ( nn_slow(domain != AF_SP && domain != AF_SP_RAW) ) // Only AF_SP and AF_SP_RAW domains are supported
        return -EAFNOSUPPORT;
    if ( nn_slow(SELF.nsocks >= NN_MAX_SOCKETS) ) // If socket limit was reached, report error
        return -EMFILE;
    s = SELF.unused [NN_MAX_SOCKETS - SELF.nsocks - 1]; //  Find an empty socket slot
    //  Find the appropriate socket type.
    for (it=nn_list_begin(&SELF.socktypes); it!=nn_list_end(&SELF.socktypes); it=nn_list_next(&SELF.socktypes, it))
    {
        socktype = nn_cont (it, struct nn_socktype, item);
        if (socktype->domain == domain && socktype->protocol == protocol)
        {
            sock = nn_alloc (sizeof (struct nn_sock), "sock"); // Instantiate the socket
            alloc_assert (sock);
            rc = nn_sock_init(sock,socktype,s);
            if ( rc < 0 )
                return rc;
            SELF.socks[s] = sock; // Adjust the global socket table
            SELF.nsocks++;
            return s;
        }
    }
    return -EINVAL; // Specified socket type wasn't found
}

int nn_socket(int domain,int protocol)
{
    int rc;
    nn_glock_lock();
    //PNACL_message("nn_socket flags.%d\n",SELF.flags);
    if (nn_slow (SELF.flags & NN_CTX_FLAG_ZOMBIE)) // If nn_term() was already called, return ETERM
    {
        nn_glock_unlock();
        errno = ETERM;
        return -1;
    }
    //PNACL_message("nn_socket flags.%d\n",SELF.flags);
    nn_global_init(); // Make sure that global state is initialised
    rc = nn_global_create_socket (domain, protocol);
    if ( rc < 0 )
    {
        nn_global_term();
        nn_glock_unlock();
        errno = -rc;
        return -1;
    }
    nn_glock_unlock();
    //PNACL_message("did nn_global_init\n");
    return rc;
}

int nn_close (int s)
{
    int rc;
    NN_BASIC_CHECKS;
    // TODO: nn_sock_term can take a long time to accomplish. It should not be performed under global critical section
    nn_glock_lock ();
    /*  Deallocate the socket object. */
    rc = nn_sock_term (SELF.socks [s]);
    if (nn_slow (rc == -EINTR)) {
        nn_glock_unlock ();
        errno = EINTR;
        return -1;
    }
    // Remove the socket from the socket table, add it to unused socket table
    nn_free (SELF.socks [s]);
    SELF.socks [s] = NULL;
    SELF.unused [NN_MAX_SOCKETS - SELF.nsocks] = s;
    --SELF.nsocks;

    /*  Destroy the global context if there's no socket remaining. */
    nn_global_term ();

    nn_glock_unlock ();

    return 0;
}

int nn_setsockopt (int s, int level, int option, const void *optval,size_t optvallen)
{
    int rc;

    NN_BASIC_CHECKS;

    if (nn_slow (!optval && optvallen)) {
        errno = EFAULT;
        return -1;
    }

    rc = nn_sock_setopt (SELF.socks [s], level, option, optval, optvallen);
    if (nn_slow (rc < 0)) {
        errno = -rc;
        return -1;
    }
    errnum_assert (rc == 0, -rc);

    return 0;
}

int nn_getsockopt (int s, int level, int option, void *optval,size_t *optvallen)
{
    int rc;

    NN_BASIC_CHECKS;

    if (nn_slow (!optval && optvallen)) {
        errno = EFAULT;
        return -1;
    }

    rc = nn_sock_getopt (SELF.socks [s], level, option, optval, optvallen);
    if (nn_slow (rc < 0)) {
        errno = -rc;
        return -1;
    }
    errnum_assert (rc == 0, -rc);

    return 0;
}

int nn_bind (int s, const char *addr)
{
    int rc;

    NN_BASIC_CHECKS;

    nn_glock_lock();
    rc = nn_global_create_ep (s, addr, 1);
    nn_glock_unlock();
    if (rc < 0) {
        errno = -rc;
        return -1;
    }

    return rc;
}

int nn_connect (int s, const char *addr)
{
    int rc;
    NN_BASIC_CHECKS;
    nn_glock_lock();
    rc = nn_global_create_ep(s, addr, 0);
    nn_glock_unlock();
    if ( rc < 0 )
    {
        errno = -rc;
        return -1;
    }
    return rc;
}

int nn_shutdown (int s, int how)
{
    int rc;

    NN_BASIC_CHECKS;

    rc = nn_sock_rm_ep (SELF.socks [s], how);
    if (nn_slow (rc < 0)) {
        errno = -rc;
        return -1;
    }
    nn_assert (rc == 0);

    return 0;
}

int32_t nn_send(int32_t s,const void *buf,size_t len,int32_t flags)
{
    struct nn_iovec iov; struct nn_msghdr hdr;
    iov.iov_base = (void*) buf;
    iov.iov_len = len;
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = NULL;
    hdr.msg_controllen = 0;
    return nn_sendmsg(s,&hdr,flags);
}

int32_t nn_recv(int32_t s,void *buf,size_t len,int32_t flags)
{
    struct nn_iovec iov;struct nn_msghdr hdr;
    iov.iov_base = buf;
    iov.iov_len = len;
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = NULL;
    hdr.msg_controllen = 0;
    return nn_recvmsg(s,&hdr,flags);
}

#ifdef NN_USE_MYMSG

int32_t nn_sendmsg(int32_t s,const struct nn_msghdr *msghdr,int32_t flags)
{
    int32_t rc,i,nnmsg; size_t sz; struct nn_iovec *iov; struct nn_msg msg; void *chunk;
    //PNACL_message("nn_sendmsg.(%d) \n",s);
    NN_BASIC_CHECKS;
    if ( nn_slow(!msghdr) )
    {
        errno = EINVAL;
        return -1;
    }
    if ( nn_slow(msghdr->msg_iovlen < 0) )
    {
        errno = EMSGSIZE;
        return -1;
    }
    if ( msghdr->msg_iovlen == 1 && msghdr->msg_iov[0].iov_len == NN_MSG )
    {
        chunk = *(void **)msghdr->msg_iov[0].iov_base;
        if ( nn_slow(chunk == NULL) )
        {
            errno = EFAULT;
            return -1;
        }
        sz = nn_chunk_size(chunk);
        nn_msg_init_chunk(&msg,chunk);
        nnmsg = 1;
    }
    else
    {
        // Compute the total size of the message
        for (sz=i=0; i<msghdr->msg_iovlen; i++)
        {
            iov = &msghdr->msg_iov[i];
            if ( nn_slow(iov->iov_len == NN_MSG) )
            {
                errno = EINVAL;
                return -1;
            }
            if ( nn_slow(!iov->iov_base && iov->iov_len) )
            {
                errno = EFAULT;
                return -1;
            }
            if ( nn_slow(sz + iov->iov_len < sz) )
            {
                errno = EINVAL;
                return -1;
            }
            sz += iov->iov_len;
        }
        //  Create a message object from the supplied scatter array
        nn_msg_init(&msg,sz);
        for (sz=i=0; i<msghdr->msg_iovlen; i++)
        {
            iov = &msghdr->msg_iov[i];
            memcpy(((uint8_t *)nn_chunkref_data(&msg.body)) + sz,iov->iov_base,iov->iov_len);
            sz += iov->iov_len;
        }
        nnmsg = 0;
    }
    nn_assert(msghdr->msg_control == 0); // cant support msgs until sendmsg()/recvmsg() native to pnacl
    rc = nn_sock_send(SELF.socks[s],&msg,flags); // Send it further down the stack
    if ( nn_slow(rc < 0) )
    {
        // If we are dealing with user-supplied buffer, detach it from the message object
        if ( nnmsg )
            nn_chunkref_init(&msg.body,0);
        nn_msg_term (&msg);
        errno = -rc;
        return -1;
    }
    // Adjust the statistics
    nn_sock_stat_increment(SELF.socks[s],NN_STAT_MESSAGES_SENT,1);
    nn_sock_stat_increment(SELF.socks[s],NN_STAT_BYTES_SENT,sz);
    return (int) sz;
}

int32_t nn_recvmsg(int32_t s,struct nn_msghdr *msghdr,int32_t flags)
{
    struct nn_msg msg; uint8_t *data; struct nn_iovec *iov; void *chunk; int32_t i,rc; size_t sz;
    NN_BASIC_CHECKS;
    if ( nn_slow(!msghdr) )
    {
        errno = EINVAL;
        return -1;
    }
    if ( nn_slow(msghdr->msg_iovlen < 0) )
    {
        errno = EMSGSIZE;
        return -1;
    }
    rc = nn_sock_recv(SELF.socks[s],&msg,flags); // Get a message
    if ( nn_slow(rc < 0) )
    {
        errno = -rc;
        return -1;
    }
    //printf("got nn_sock_recv rc.%d\n",rc);
    if ( msghdr->msg_iovlen == 1 && msghdr->msg_iov[0].iov_len == NN_MSG )
    {
        chunk = nn_chunkref_getchunk(&msg.body);
        *(void **)(msghdr->msg_iov[0].iov_base) = chunk;
        sz = nn_chunk_size(chunk);
        //PNACL_message("got message -> iov_base.%p sz.%d\n",msghdr->msg_iov[0].iov_base,(int32_t)sz);
    }
    else // Copy the message content into the supplied gather array
    {
        data = nn_chunkref_data(&msg.body);
        sz = nn_chunkref_size(&msg.body);
        //PNACL_message("got message -> data.%p sz.%d\n",data,(int32_t)sz);
        for (i=0; i!=msghdr->msg_iovlen; i++)
        {
            iov = &msghdr->msg_iov[i];
            if ( nn_slow(iov->iov_len == NN_MSG) )
            {
                nn_msg_term(&msg);
                errno = EINVAL;
                return -1;
            }
            if ( iov->iov_len > sz )
            {
                memcpy(iov->iov_base,data,sz);
                break;
            }
            memcpy(iov->iov_base,data,iov->iov_len);
            data += iov->iov_len;
            sz -= iov->iov_len;
        }
        sz = nn_chunkref_size(&msg.body);
    }
    nn_assert(msghdr->msg_control == 0); // cant support msgs until sendmsg()/recvmsg() native to pnacl
    nn_msg_term(&msg);
    return (int32_t)sz;
}

#else

int32_t nn_sendmsg(int32_t s,const struct nn_msghdr *msghdr,int32_t flags)
{
    int32_t rc,i,nnmsg; size_t sz,spsz; struct nn_iovec *iov; struct nn_msg msg; void *chunk; struct nn_cmsghdr *cmsg;
    //PNACL_message("nn_sendmsg.(%d) \n",s);
    NN_BASIC_CHECKS;
    if ( nn_slow(!msghdr) )
    {
        errno = EINVAL;
        return -1;
    }
    if ( nn_slow(msghdr->msg_iovlen < 0) )
    {
        errno = EMSGSIZE;
        return -1;
    }
    if ( msghdr->msg_iovlen == 1 && msghdr->msg_iov [0].iov_len == NN_MSG )
    {
        chunk = *(void **)msghdr->msg_iov[0].iov_base;
        if ( nn_slow(chunk == NULL) )
        {
            errno = EFAULT;
            return -1;
        }
        sz = nn_chunk_size(chunk);
        nn_msg_init_chunk(&msg,chunk);
        nnmsg = 1;
    }
    else
    {
        // Compute the total size of the message
        sz = 0;
        for (i = 0; i != msghdr->msg_iovlen; ++i)
        {
            iov = &msghdr->msg_iov[i];
            if ( nn_slow(iov->iov_len == NN_MSG) )
            {
               errno = EINVAL;
               return -1;
            }
            if ( nn_slow(!iov->iov_base && iov->iov_len) )
            {
                errno = EFAULT;
                return -1;
            }
            if ( nn_slow(sz + iov->iov_len < sz) )
            {
                errno = EINVAL;
                return -1;
            }
            sz += iov->iov_len;
        }
        //  Create a message object from the supplied scatter array
        nn_msg_init(&msg,sz);
        sz = 0;
        for (i = 0; i != msghdr->msg_iovlen; ++i) {
            iov = &msghdr->msg_iov [i];
            memcpy (((uint8_t*) nn_chunkref_data (&msg.body)) + sz,
                iov->iov_base, iov->iov_len);
            sz += iov->iov_len;
        }

        nnmsg = 0;
    }

    /*  Add ancillary data to the message. */
    if (msghdr->msg_control) {

        /*  Copy all headers. */
        /*  TODO: SP_HDR should not be copied here! */
        if (msghdr->msg_controllen == NN_MSG) {
            chunk = *((void**) msghdr->msg_control);
            nn_chunkref_term (&msg.hdrs);
            nn_chunkref_init_chunk (&msg.hdrs, chunk);
        }
        else {
            nn_chunkref_term (&msg.hdrs);
            nn_chunkref_init (&msg.hdrs, msghdr->msg_controllen);
            memcpy (nn_chunkref_data (&msg.hdrs),
                msghdr->msg_control, msghdr->msg_controllen);
        }

        /* Search for SP_HDR property. */
        cmsg = NN_CMSG_FIRSTHDR (msghdr);
        while (cmsg) {
            if (cmsg->cmsg_level == PROTO_SP && cmsg->cmsg_type == SP_HDR) {
                /*  Copy body of SP_HDR property into 'sphdr'. */
                nn_chunkref_term (&msg.sphdr);
                spsz = cmsg->cmsg_len - NN_CMSG_SPACE (0);
                nn_chunkref_init (&msg.sphdr, spsz);
                memcpy (nn_chunkref_data (&msg.sphdr),
                    NN_CMSG_DATA (cmsg), spsz);
                break;
            }
            cmsg = NN_CMSG_NXTHDR (msghdr, cmsg);
        }
    }

    /*  Send it further down the stack. */
    rc = nn_sock_send (SELF.socks [s], &msg, flags);
    if (nn_slow (rc < 0)) {

        /*  If we are dealing with user-supplied buffer, detach it from
            the message object. */
        if (nnmsg)
            nn_chunkref_init (&msg.body, 0);

        nn_msg_term (&msg);
        errno = -rc;
        return -1;
    }

    /*  Adjust the statistics. */
    nn_sock_stat_increment (SELF.socks [s], NN_STAT_MESSAGES_SENT, 1);
    nn_sock_stat_increment (SELF.socks [s], NN_STAT_BYTES_SENT, sz);

    return (int) sz;
}

int32_t nn_recvmsg(int32_t s,struct nn_msghdr *msghdr,int32_t flags)
{
    struct nn_msg msg; uint8_t *data; struct nn_iovec *iov; void *chunk,*ctrl; struct nn_cmsghdr *chdr;
    int32_t i,rc; size_t sz,hdrssz,ctrlsz,spsz,sptotalsz;
    //PNACL_message("nn_recvmsg.(%d) \n",s);
    NN_BASIC_CHECKS;
    if ( nn_slow(!msghdr) )
    {
        errno = EINVAL;
        return -1;
    }
    if ( nn_slow(msghdr->msg_iovlen < 0) )
    {
        errno = EMSGSIZE;
        return -1;
    }
    //PNACL_message("get a message from sock.%d\n",s);
    rc = nn_sock_recv(SELF.socks[s],&msg,flags); // Get a message
    if ( nn_slow(rc < 0) )
    {
        errno = -rc;
        return -1;
    }
    if ( msghdr->msg_iovlen == 1 && msghdr->msg_iov[0].iov_len == NN_MSG )
    {
        chunk = nn_chunkref_getchunk(&msg.body);
        *(void **)(msghdr->msg_iov[0].iov_base) = chunk;
        sz = nn_chunk_size(chunk);
        //PNACL_message("got message -> iov_base.%p sz.%d\n",msghdr->msg_iov[0].iov_base,(int32_t)sz);
    }
    else // Copy the message content into the supplied gather array
    {
        data = nn_chunkref_data(&msg.body);
        sz = nn_chunkref_size (&msg.body);
        //PNACL_message("got message -> data.%p sz.%d\n",data,(int32_t)sz);
        for (i=0; i!=msghdr->msg_iovlen; i++)
        {
            iov = &msghdr->msg_iov[i];
            if ( nn_slow(iov->iov_len == NN_MSG) )
            {
                nn_msg_term(&msg);
                errno = EINVAL;
                return -1;
            }
            if ( iov->iov_len > sz )
            {
                memcpy(iov->iov_base,data,sz);
                break;
            }
            memcpy(iov->iov_base,data,iov->iov_len);
            data += iov->iov_len;
            sz -= iov->iov_len;
        }
        sz = nn_chunkref_size(&msg.body);
    }
    //  Retrieve the ancillary data from the message
    if ( msghdr->msg_control )
    {
        spsz = nn_chunkref_size(&msg.sphdr);
        sptotalsz = NN_CMSG_SPACE(spsz);
        ctrlsz = sptotalsz + nn_chunkref_size(&msg.hdrs);
        if ( msghdr->msg_controllen == NN_MSG )
        {
            rc = nn_chunk_alloc (ctrlsz, 0, &ctrl); // Allocate the buffer
            errnum_assert (rc == 0, -rc);
            *((void**) msghdr->msg_control) = ctrl; // Set output parameters
        }
        else
        {
            ctrl = msghdr->msg_control; // Just use the buffer supplied by the user
            ctrlsz = msghdr->msg_controllen;
        }
        // If SP header alone won't fit into the buffer, return no ancillary properties
        if ( ctrlsz >= sptotalsz ) // Fill in SP_HDR ancillary property
        {
            chdr = (struct nn_cmsghdr*) ctrl;
            chdr->cmsg_len = sptotalsz;
            chdr->cmsg_level = PROTO_SP;
            chdr->cmsg_type = SP_HDR;
            memcpy(chdr + 1,nn_chunkref_data(&msg.sphdr),spsz);
            //  Fill in as many remaining properties as possible. Truncate the trailing properties if necessary
            hdrssz = nn_chunkref_size(&msg.hdrs);
            if ( hdrssz > ctrlsz - sptotalsz )
                hdrssz = ctrlsz - sptotalsz;
            memcpy(((char*) ctrl) + sptotalsz,nn_chunkref_data(&msg.hdrs),hdrssz);
        }
    }
    nn_msg_term(&msg);
    return (int32_t)sz;
}
#endif

static void nn_global_add_transport (struct nn_transport *transport)
{
    if (transport->init)
        transport->init ();
    nn_list_insert (&SELF.transports, &transport->item,
        nn_list_end (&SELF.transports));

}

static void nn_global_add_socktype (struct nn_socktype *socktype)
{
    nn_list_insert (&SELF.socktypes, &socktype->item,
        nn_list_end (&SELF.socktypes));
}

static void nn_global_submit_counter (int i, struct nn_sock *s,
    char *name, uint64_t value)
{
    /* Length of buffer is:
       len(hostname) + len(appname) + len(socket_name) + len(timebuf)
       + len(str(value)) + len(static characters)
       63 + 63 + 63 + 20 + 20 + 60 = 289 */
    char buf[512];
    char timebuf[20];
    time_t numtime;
    struct tm strtime;
    int len;

    if(SELF.print_statistics) {
        fprintf(stderr, "nanomsg: socket.%s: %s: %llu\n",
            s->socket_name, name, (long long unsigned int)value);
    }

    if (SELF.statistics_socket >= 0) {
        /*  TODO(tailhook) add HAVE_GMTIME_R ifdef  */
        time(&numtime);
#ifdef NN_HAVE_GMTIME_R
        gmtime_r (&numtime, &strtime);
#else
#error
#endif
        strftime (timebuf, 20, "%Y-%m-%dT%H:%M:%S", &strtime);
        if(*s->socket_name) {
            len = sprintf (buf, "ESTP:%s:%s:socket.%s:%s: %sZ 10 %llu:c",
                SELF.hostname, SELF.appname, s->socket_name, name,
                timebuf, (long long unsigned int)value);
        } else {
            len = sprintf (buf, "ESTP:%s:%s:socket.%d:%s: %sZ 10 %llu:c",
                SELF.hostname, SELF.appname, i, name,
                timebuf, (long long unsigned int)value);
        }
        nn_assert (len < (int)sizeof(buf));
        (void) nn_send (SELF.statistics_socket, buf, len, NN_DONTWAIT);
    }
}

static void nn_global_submit_level (int i, struct nn_sock *s,
    char *name, int value)
{
    /* Length of buffer is:
       len(hostname) + len(appname) + len(socket_name) + len(timebuf)
       + len(str(value)) + len(static characters)
       63 + 63 + 63 + 20 + 20 + 60 = 289 */
    char buf[512];
    char timebuf[20];
    time_t numtime;
    struct tm strtime;
    int len;

    if(SELF.print_statistics) {
        fprintf(stderr, "nanomsg: socket.%s: %s: %d\n",
            s->socket_name, name, value);
    }

    if (SELF.statistics_socket >= 0) {
        /*  TODO(tailhook) add HAVE_GMTIME_R ifdef  */
        time(&numtime);
#ifdef NN_HAVE_GMTIME_R
        gmtime_r (&numtime, &strtime);
#else
#error
#endif
        strftime (timebuf, 20, "%Y-%m-%dT%H:%M:%S", &strtime);
        if(*s->socket_name) {
            len = sprintf (buf, "ESTP:%s:%s:socket.%s:%s: %sZ 10 %d",
                SELF.hostname, SELF.appname, s->socket_name, name,
                timebuf, value);
        } else {
            len = sprintf (buf, "ESTP:%s:%s:socket.%d:%s: %sZ 10 %d",
                SELF.hostname, SELF.appname, i, name,
                timebuf, value);
        }
        nn_assert (len < (int)sizeof(buf));
        (void) nn_send (SELF.statistics_socket, buf, len, NN_DONTWAIT);
    }
}

static void nn_global_submit_errors (int i, struct nn_sock *s,
    char *name, int value)
{
    /*  TODO(tailhook) dynamically allocate buffer  */
    char buf[4096];
    char *curbuf;
    int buf_left;
    char timebuf[20];
    time_t numtime;
    struct tm strtime;
    int len;
    struct nn_list_item *it;
    struct nn_ep *ep;

    if (SELF.statistics_socket >= 0) {
        /*  TODO(tailhook) add HAVE_GMTIME_R ifdef  */
        time(&numtime);
#ifdef NN_HAVE_GMTIME_R
        gmtime_r (&numtime, &strtime);
#else
#error
#endif
        strftime (timebuf, 20, "%Y-%m-%dT%H:%M:%S", &strtime);
        if(*s->socket_name) {
            len = sprintf (buf, "ESTP:%s:%s:socket.%s:%s: %sZ 10 %d\n",
                SELF.hostname, SELF.appname, s->socket_name, name,
                timebuf, value);
        } else {
            len = sprintf (buf, "ESTP:%s:%s:socket.%d:%s: %sZ 10 %d\n",
                SELF.hostname, SELF.appname, i, name,
                timebuf, value);
        }
        buf_left = sizeof(buf) - len;
        curbuf = buf + len;


        for (it = nn_list_begin (&s->eps);
              it != nn_list_end (&s->eps);
              it = nn_list_next (&s->eps, it)) {
            ep = nn_cont (it, struct nn_ep, item);

            if (ep->last_errno) {
#ifdef NN_HAVE_WINDOWS
                len = _snprintf_s (curbuf, buf_left, _TRUNCATE,
                    " nanomsg: Endpoint %d [%s] error: %s\n",
                    ep->eid, nn_ep_getaddr (ep), nn_strerror (ep->last_errno));
#else
                 len = snprintf (curbuf, buf_left,
                     " nanomsg: Endpoint %d [%s] error: %s\n",
                     ep->eid, nn_ep_getaddr (ep), nn_strerror (ep->last_errno));
                PNACL_message("%s\n",curbuf);
#endif
                if (buf_left < len)
                    break;
                curbuf += len;
                buf_left -= len;
            }

        }

        (void) nn_send (SELF.statistics_socket,
            buf, sizeof(buf) - buf_left, NN_DONTWAIT);
    }
}

static void nn_global_submit_statistics ()
{
    int i;
    struct nn_sock *s;

    /*  TODO(tailhook)  optimized it to use nsocks and unused  */
    for(i = 0; i < NN_MAX_SOCKETS; ++i) {

        nn_glock_lock ();
        s = SELF.socks [i];
        if (!s) {
            nn_glock_unlock ();
            continue;
        }
        if (i == SELF.statistics_socket) {
            nn_glock_unlock ();
            continue;
        }
        nn_ctx_enter (&s->ctx);
        nn_glock_unlock ();

        nn_global_submit_counter (i, s,
            "established_connections", s->statistics.established_connections);
        nn_global_submit_counter (i, s,
            "accepted_connections", s->statistics.accepted_connections);
        nn_global_submit_counter (i, s,
            "dropped_connections", s->statistics.dropped_connections);
        nn_global_submit_counter (i, s,
            "broken_connections", s->statistics.broken_connections);
        nn_global_submit_counter (i, s,
            "connect_errors", s->statistics.connect_errors);
        nn_global_submit_counter (i, s,
            "bind_errors", s->statistics.bind_errors);
        nn_global_submit_counter (i, s,
            "accept_errors", s->statistics.accept_errors);
        nn_global_submit_counter (i, s,
            "messages_sent", s->statistics.messages_sent);
        nn_global_submit_counter (i, s,
            "messages_received", s->statistics.messages_received);
        nn_global_submit_counter (i, s,
            "bytes_sent", s->statistics.bytes_sent);
        nn_global_submit_counter (i, s,
            "bytes_received", s->statistics.bytes_received);
        nn_global_submit_level (i, s,
            "current_connections", s->statistics.current_connections);
        nn_global_submit_level (i, s,
            "inprogress_connections", s->statistics.inprogress_connections);
        nn_global_submit_level (i, s,
            "current_snd_priority", s->statistics.current_snd_priority);
        nn_global_submit_errors (i, s,
            "current_ep_errors", s->statistics.current_ep_errors);
        nn_ctx_leave (&s->ctx);
    }
}

static int nn_global_create_ep (int s, const char *addr, int bind)
{
    int rc;
    const char *proto;
    const char *delim;
    size_t protosz;
    struct nn_transport *tp;
    struct nn_list_item *it;

    /*  Check whether address is valid. */
    if (!addr)
        return -EINVAL;
    if (strlen (addr) >= NN_SOCKADDR_MAX)
        return -ENAMETOOLONG;

    /*  Separate the protocol and the actual address. */
    proto = addr;
    delim = strchr (addr, ':');
    if (!delim)
        return -EINVAL;
    if (delim [1] != '/' || delim [2] != '/')
        return -EINVAL;
    protosz = delim - addr;
    addr += protosz + 3;
#ifdef NN_USE_MYMSG
    if ( strncmp("inproc",proto,strlen("inproc")) != 0 && strncmp("ipc",proto,strlen("ipc")) != 0 && strncmp("tcp",proto,strlen("tcp")) != 0 )
    {
        PNACL_message("only ipc, inproc and tcp transport is supported\n");
        printf("only ipc, inproc and tcp transport is supported\n");
        fprintf(stderr,"only ipc, inproc and tcp transport is supported\n");
        exit(-1);
        return -EPROTONOSUPPORT;
    }
#endif
    //printf("protocol.(%s)\n",proto);
    /*  Find the specified protocol. */
    tp = NULL;
    for (it = nn_list_begin (&SELF.transports);
          it != nn_list_end (&SELF.transports);
          it = nn_list_next (&SELF.transports, it)) {
        tp = nn_cont (it, struct nn_transport, item);
        if (strlen (tp->name) == protosz &&
              memcmp (tp->name, proto, protosz) == 0)
            break;
        tp = NULL;
    }
    if ( !tp ) // The protocol specified doesn't match any known protocol
        return -EPROTONOSUPPORT;
    rc = nn_sock_add_ep (SELF.socks [s], tp, bind, addr); // Ask the socket to create the endpoint
    return rc;
}

struct nn_transport *nn_global_transport (int id)
{
    struct nn_transport *tp;
    struct nn_list_item *it;

    /*  Find the specified protocol. */
    tp = NULL;
    nn_glock_lock ();
    for (it = nn_list_begin (&SELF.transports);
          it != nn_list_end (&SELF.transports);
          it = nn_list_next (&SELF.transports, it)) {
        tp = nn_cont (it, struct nn_transport, item);
        if (tp->id == id)
            break;
        tp = NULL;
    }
    nn_glock_unlock ();

    return tp;
}

struct nn_pool *nn_global_getpool ()
{
    return &SELF.pool;
}

static void nn_global_handler (struct nn_fsm *myself,int src, int type, NN_UNUSED void *srcptr)
{

    struct nn_global *global;

    global = nn_cont (myself, struct nn_global, fsm);

    switch ( global->state )
    {
/******************************************************************************/
/*  IDLE state.                                                               */
/*  The state machine wasn't yet started.                                     */
/******************************************************************************/
    case NN_GLOBAL_STATE_IDLE:
        switch (src)
        {

        case NN_FSM_ACTION:
            switch ( type )
            {
            case NN_FSM_START:
                global->state = NN_GLOBAL_STATE_ACTIVE;
                if ( global->print_statistics || global->statistics_socket >= 0 )
                    nn_timer_start (&global->stat_timer, 10000); // Start statistics collection timer
                return;
            default:
                    PNACL_message("bad action %d type %d\n",src,type);
                nn_fsm_bad_action(global->state, src, type);
            }

        default:
                PNACL_message("bad source %d\n",src);
                nn_fsm_bad_source(global->state, src, type);
        }

/******************************************************************************/
/*  ACTIVE state.                                                             */
/*  Normal lifetime for global object.                                        */
/******************************************************************************/
    case NN_GLOBAL_STATE_ACTIVE:
        switch (src) {

        case NN_GLOBAL_SRC_STAT_TIMER:
            switch (type) {
            case NN_TIMER_TIMEOUT:
                nn_global_submit_statistics ();
                /*  No need to change state  */
                nn_timer_stop (&global->stat_timer);
                return;
            case NN_TIMER_STOPPED:
                nn_timer_start (&global->stat_timer, 10000);
                return;
            default:
                nn_fsm_bad_action (global->state, src, type);
            }

        default:
            nn_fsm_bad_source (global->state, src, type);
        }

/******************************************************************************/
/*  Invalid state.                                                            */
/******************************************************************************/
    default:
        nn_fsm_bad_state (global->state, src, type);
    }
}

static void nn_global_shutdown (struct nn_fsm *myself,NN_UNUSED int src, NN_UNUSED int type, NN_UNUSED void *srcptr)
{

    struct nn_global *global;

    global = nn_cont (myself, struct nn_global, fsm);

    nn_assert (global->state == NN_GLOBAL_STATE_ACTIVE
        || global->state == NN_GLOBAL_STATE_IDLE);
    if (global->state == NN_GLOBAL_STATE_ACTIVE) {
        if (!nn_timer_isidle (&global->stat_timer)) {
            nn_timer_stop (&global->stat_timer);
            return;
        }
    }
}

int32_t nn_global_print_errors() { return SELF.print_errors; }
