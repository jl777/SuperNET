/******************************************************************************
 * Copyright © 2014-2016 The SuperNET Developers.                             *
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

#include "../../includes/cJSON.h"
#include "cdb-0.75/alloc.c"
#include "cdb-0.75/buffer.c"
#include "cdb-0.75/buffer_copy.c"
#include "cdb-0.75/buffer_put.c"
#include "cdb-0.75/buffer_get.c"
#include "cdb-0.75/byte_copy.c"
#include "cdb-0.75/byte_cr.c"
#include "cdb-0.75/byte_diff.c"
#include "cdb-0.75/cdb.c"
#include "cdb-0.75/cdb_hash.c"
#include "cdb-0.75/cdb_make.c"
#include "cdb-0.75/uint32_pack.c"
#include "cdb-0.75/uint32_unpack.c"
#include "cdb-0.75/str_len.c"
#include "cdb-0.75/seek_cur.c"
#include "cdb-0.75/seek_set.c"
#include "cdb-0.75/open_read.c"
#include "cdb-0.75/open_trunc.c"

int32_t cdb_jsonmake(cJSON *array,char *dest,char *tmpname)
{
    uint32_t klen,dlen,i,n,h; char *field,*value; int32_t fd; cJSON *item; struct cdb_make cdb;
    memset(&cdb,0,sizeof(cdb));
    if ( (fd= open_trunc(tmpname)) == -1 )
        return(-1);
    if ( cdb_make_start(&cdb,fd) == -1 )
    {
        close(fd);
        return(-2);
    }
    if ( (n= cJSON_GetArraySize(array)) > 0 )
    {
        for (i=0; i<n; i++)
        {
            item = jitem(array,i);
            if ( (field= jfieldname(item)) != 0 && (klen= str_len(field)) > 0)
            {
                value = jprint(item,0);
                if ( (dlen= str_len(value)) > 0 )
                {
                    if ( klen > 429496720 || dlen > 429496720 || cdb_make_addbegin(&cdb,klen,dlen) == -1 )
                    {
                        close(fd);
                        free(value);
                        return(-3);
                    }
                    h = CDB_HASHSTART;
                    for (i=0; i<klen; i++)
                    {
                        if ( buffer_PUTC(&cdb.b,field[i]) == -1)
                        {
                            close(fd);
                            free(value);
                            return(-3);
                        }
                        h = cdb_hashadd(h,field[i]);
                    }
                    for (i=0; i<dlen; i++)
                    {
                        if ( buffer_PUTC(&cdb.b,value[i]) == -1 )
                            break;
                    }
                    if ( i != dlen || cdb_make_addend(&cdb,klen,dlen,h) == -1 )
                    {
                        close(fd);
                        free(value);
                        return(-4);
                    }
                }
                free(value);
            }
        }
    }
    if ( cdb_make_finish(&cdb) == -1 || fsync(fd) == -1 || close(fd) == -1 )
        return(-5);
    if ( rename(tmpname,dest) == -1 )
        return(-6);
    return(0);
}
