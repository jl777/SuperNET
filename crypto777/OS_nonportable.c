/******************************************************************************
 * Copyright © 2014-2015 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

 
#include "OS_portable.h"

#ifdef __PNACL
int32_t OS_nonportable_syncmap(struct OS_mappedptr *mp,long len)
{
    printf("no way to sync mapped mem in pnacl\n");
    return(-1);
}

void *OS_nonportable_tmpalloc(char *dirname,char *name,struct OS_memspace *mem,long origsize)
{
    printf("no way to do tmpallocs in pnacl\n");
    return(0);
}

#elif _WIN32
#include <sys/mman.h>
#include <io.h>
#include <share.h>
#include <errno.h>
#include <string.h>
#include <windows.h>
#include <inttypes.h>
#include <winsock2.h>
#include <in6addr.h>
#include <ws2tcpip.h>
#include <errno.h>
#include <fcntl.h> /*  _O_BINARY */
#include <stdlib.h>
#include <wincrypt.h>
#include <stdio.h>
#include <process.h>
#include <tlhelp32.h>
#include <time.h>

char *OS_nonportable_path(char *str)
{
    int32_t i;
    for (i=0; str[i]!=0; i++)
        if ( str[i] == '/' )
            str[i] = '\\';
    return(str);
}

void *OS_nonportable_mapfile(char *fname,uint64_t *filesizep,int32_t enablewrite)
{
	int32_t fd,rwflags,flags = MAP_FILE|MAP_SHARED;
	uint64_t filesize;
    void *ptr = 0;
	*filesizep = 0;
	if ( enablewrite != 0 )
		fd = _sopen(fname, _O_RDWR | _O_BINARY, _SH_DENYNO);
	else fd = _sopen(fname, _O_RDONLY | _O_BINARY, _SH_DENYNO);
	if ( fd < 0 )
	{
		//printf("map_file: error opening enablewrite.%d %s\n",enablewrite,fname);
        return(0);
	}
    if ( *filesizep == 0 )
        filesize = (uint64_t)lseek(fd,0,SEEK_END);
    else filesize = *filesizep;
 	rwflags = PROT_READ;
	if ( enablewrite != 0 )
		rwflags |= PROT_WRITE;
	ptr = mmap(0,filesize,rwflags,flags,fd,0);
	_close(fd);
    if ( ptr == 0 || ptr == MAP_FAILED )
	{
		printf("map_file.write%d: mapping %s failed? mp %p\n",enablewrite,fname,ptr);
		return(0);
	}
	*filesizep = filesize;
	return(ptr);
}

int32_t OS_nonportable_renamefile(char *fname,char *newfname)
{
    char cmdstr[1024],tmp[512];
    strcpt(tmp,fname);
    OS_nonportable_path(tmp);
    sprintf(cmdstr,"del %s",tmp);
    if ( system() != 0 )
        printf("error deleting file.(%s)\n",cmdstr);
    else return(1);
}

int32_t  OS_nonportable_launch(char *args[])
{
    int32_t pid;
    pid = _spawnl( _P_NOWAIT, args[0], args[0],  NULL, NULL );
    return pid;
}

void OS_nonportable_randombytes(unsigned char *x,long xlen)
{
    HCRYPTPROV prov = 0;
    CryptAcquireContextW(&prov, NULL, NULL,PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
    CryptGenRandom(prov, xlen, x);
    CryptReleaseContext(prov, 0);
}

int32_t OS_nonportable_init()
{
    // Initialize Windows Sockets
    WSADATA wsadata;
    int ret = WSAStartup(MAKEWORD(2,2), &wsadata);
    if (ret != NO_ERROR)
    {
        printf("Error: TCP/IP socket library failed to start (WSAStartup returned error %d)\n", ret);
        //printf("%s\n", strError.c_str());
        return -1;
    }
    return(0);
}

#else
void OS_nonportable_none() { printf("unix is the reference OS\n"); }

#endif

