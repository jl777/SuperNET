#ifndef MINGW_H
#define MINGW_H

#define ssize_t __int32
#include <io.h>

#define _USE_W32_SOCKETS 1
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#define PTW32_STATIC_LIB
#include "pthread.h"

#ifndef NATIVE_WINDOWS
#define ENOTCONN        WSAENOTCONN
#define EWOULDBLOCK     WSAEWOULDBLOCK
#define ENOBUFS         WSAENOBUFS
#define ECONNRESET      WSAECONNRESET
#define ESHUTDOWN       WSAESHUTDOWN
#define EAFNOSUPPORT    WSAEAFNOSUPPORT
#define EPROTONOSUPPORT WSAEPROTONOSUPPORT
#define EINPROGRESS     WSAEINPROGRESS
#define EISCONN         WSAEISCONN
#define ECONNREFUSED    WSAECONNREFUSED
#define EHOSTUNREACH    WSAEHOSTUNREACH
#endif

/* winsock doesn't feature poll(), so there is a version implemented
 * in terms of select() in mingw.c. The following definitions
 * are copied from linux man pages. A poll() macro is defined to
 * call the version in mingw.c.
 */

#define POLLPRI     0x0002    /* There is urgent data to read */
#if defined(_M_X64)
 /*
 * when we are using WSAPoll() with window's struct pollfd struct
 * we need to update the value for POLLIN and POLLOUT according to window's
 * WSAPoll() return values
 * @author - fadedreamz@gmail.com
 */
//TODO: need to update other values to match with WSAPoll() function 
#define POLLRDNORM  0x0100
#define POLLRDBAND  0x0200
#define POLLWRNORM  0x0010
#define POLLIN      POLLRDNORM | POLLRDBAND     /* There is data to read */
#define POLLOUT     POLLWRNORM    /* Writing now will not block */
#else
#define POLLIN      0x0001    /* There is data to read */
#define POLLOUT     0x0004    /* Writing now will not block */
#endif
#define POLLERR     0x0008    /* Error condition */
#define POLLHUP     0x0010    /* Hung up */
#define POLLNVAL    0x0020    /* Invalid request: fd not open */

 /**
 * we want to use mingw provided pollfd if and only if we are compiling this 
 * in windows 32bit but exclude it when we are compiling it in win 64
 *
 * @author - fadedreamz@gmail.com
 * @remarks - #if (defined(_M_X64) || defined(__amd64__)) && defined(WIN32)
 *     is equivalent to #if defined(_M_X64) as _M_X64 is defined for MSVC only
 */
#if !defined(_M_X64)
struct pollfd {
    SOCKET fd;        /* file descriptor */
    short events;     /* requested events */
    short revents;    /* returned events */
};
#endif

#if defined(_M_X64)
/*
* we want to use the window's poll function if poll() is invoked in win64
* as we are using window's pollfd struct when we are using x64
* @author - fadedreamz@gmail.com
*/
#define poll(x, y, z)        WSAPoll(x, y, z)
#else
#define poll(x, y, z)        win32_poll(x, y, z)
#endif

/* These wrappers do nothing special except set the global errno variable if
 * an error occurs (winsock doesn't do this by default). They set errno
 * to unix-like values (i.e. WSAEWOULDBLOCK is mapped to EAGAIN), so code
 * outside of this file "shouldn't" have to worry about winsock specific error
 * handling.
 */
//#define socket(x, y, z)		win32_socket(x, y, z)
//#define connect(x, y, z)	win32_connect(x, y, z)
//#define accept(x, y, z)		win32_accept(x, y, z)
//#define shutdown(x, y)		win32_shutdown(x, y)
//#define read(x, y, z)			win32_read_socket(x, y, z)
//#define write(x, y, z)			win32_write_socket(x, y, z)

/* Winsock uses int instead of the usual socklen_t */
typedef int socklen_t;

int     win32_poll(struct pollfd *, unsigned int, int);
//SOCKET  win32_socket(int, int, int);
//int     win32_connect(SOCKET, struct sockaddr*, socklen_t);
//SOCKET  win32_accept(SOCKET, struct sockaddr*, socklen_t *);
//int     win32_shutdown(SOCKET, int);
//int 	win32_close_socket(SOCKET fd);

//#define strtok_r(x, y, z)      win32_strtok_r(x, y, z)
//#define strsep(x,y) win32_strsep(x,y)

char *win32_strtok_r(char *s, const char *delim, char **lasts);
char *win32_strsep(char **stringp, const char *delim);

ssize_t win32_read_socket(SOCKET fd, void *buf, int n);
ssize_t win32_write_socket(SOCKET fd, void *buf, int n);

//static inline void sleep(unsigned ms) { Sleep(ms*1000); }

#endif

