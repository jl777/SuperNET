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

#include "peggy.h"

void ramkv777_lock(struct ramkv777 *kv)
{
    if ( kv->threadsafe != 0 )
        portable_mutex_lock(&kv->mutex);
}

void ramkv777_unlock(struct ramkv777 *kv)
{
    if ( kv->threadsafe != 0 )
        portable_mutex_unlock(&kv->mutex);
}

int32_t ramkv777_delete(struct ramkv777 *kv,void *key)
{
    int32_t retval = -1; struct ramkv777_item *ptr = 0;
    if ( kv == 0 )
        return(-1);
    ramkv777_lock(kv);
    HASH_FIND(hh,kv->table,key,kv->keysize,ptr);
    if ( ptr != 0 )
    {
        HASH_DELETE(hh,kv->table,ptr);
        free(ptr);
        retval = 0;
    }
    ramkv777_lock(kv);
    return(retval);
}

void *ramkv777_read(int32_t *valuesizep,struct ramkv777 *kv,void *key)
{
    struct ramkv777_item *item = 0;
    if ( kv == 0 )
    {
        printf("ramkv777_read: null ramkv??\n");
        return(0);
    }
    //printf("search for [%llx] keysize.%d\n",*(long long *)key,keysize);
    ramkv777_lock(kv);
    HASH_FIND(hh,kv->table,key,kv->keysize,item);
    ramkv777_unlock(kv);
    if ( item != 0 )
    {
        if ( valuesizep != 0 )
            *valuesizep = item->valuesize;
        return(ramkv777_itemvalue(kv,item));
    } //else printf("cant find key.%llx keysize.%d\n",*(long long *)key,kv->keysize);
    if ( valuesizep != 0 )
        *valuesizep = 0;
    return(0);
}

void *ramkv777_write(struct ramkv777 *kv,void *key,void *value,int32_t valuesize)
{
    struct ramkv777_item *item = 0; int32_t keysize = kv->keysize;
    if ( kv == 0 )
        return(0);
    ramkv777_lock(kv);
    HASH_FIND(hh,kv->table,key,keysize,item);
    if ( item != 0 )
    {
        printf("item being added, already there\n");
        if ( valuesize == item->valuesize )
        {
            if ( memcmp(ramkv777_itemvalue(kv,item),value,valuesize) != 0 )
            {
                vupdate_sha256(kv->sha256.bytes,&kv->state,key,kv->keysize);
                vupdate_sha256(kv->sha256.bytes,&kv->state,value,valuesize);
                memcpy(ramkv777_itemvalue(kv,item),value,valuesize);
            }
            ramkv777_unlock(kv);
            return(item);
        }
        HASH_DELETE(hh,kv->table,item);
        free(item);
        vupdate_sha256(kv->sha256.bytes,&kv->state,key,kv->keysize);
    }
    item = calloc(1,ramkv777_itemsize(kv,valuesize));
    memcpy(item->keyvalue,key,kv->keysize);
    memcpy(ramkv777_itemvalue(kv,item),value,valuesize);
    item->valuesize = valuesize;
    item->rawind = (kv->numkeys++ * ACCTS777_MAXRAMKVS) | kv->kvind;
    //printf("add.(%s) kv->numkeys.%d keysize.%d valuesize.%d [%llx]\n",kv->name,kv->numkeys,keysize,valuesize,*(long long *)ramkv777_itemkey(item));
    HASH_ADD_KEYPTR(hh,kv->table,ramkv777_itemkey(item),kv->keysize,item);
    vupdate_sha256(kv->sha256.bytes,&kv->state,key,kv->keysize);
    vupdate_sha256(kv->sha256.bytes,&kv->state,value,valuesize);
    ramkv777_unlock(kv);
    if ( kv->dispflag != 0 )
        fprintf(stderr,"%016llx ramkv777_write numkeys.%d kv.%p table.%p write kep.%p key.%llx size.%d, value.(%08x) size.%d\n",(long long)kv->sha256.txid,kv->numkeys,kv,kv->table,key,*(long long *)key,keysize,calc_crc32(0,value,valuesize),valuesize);
    return(ramkv777_itemvalue(kv,item));
}

void *ramkv777_iterate(struct ramkv777 *kv,void *args,void *(*iterator)(struct ramkv777 *kv,void *args,void *key,void *value,int32_t valuesize))
{
    struct ramkv777_item *item,*tmp; void *retval = 0;
    if ( kv == 0 )
        return(0);
    ramkv777_lock(kv);
    HASH_ITER(hh,kv->table,item,tmp)
    {
        if ( (retval= (*iterator)(kv,args!=0?args:item,item->keyvalue,ramkv777_itemvalue(kv,item),item->valuesize)) != 0 )
        {
            ramkv777_unlock(kv);
            return(retval);
        }
    }
    ramkv777_unlock(kv);
    return(0);
}

void *ramkv777_saveiterator(struct ramkv777 *kv,void *args,void *key,void *value,int32_t valuesize)
{
    FILE *fp = args;
    if ( args != 0 )
    {
        if ( fwrite(key,1,kv->keysize,fp) != kv->keysize )
        {
            printf("Error saving key.[%d]\n",kv->keysize);
            return(key);
        }
    }
    return(0);
}

/*char *OS_mvstr()
{
#ifdef __WIN32
    return("rename");
#else
    return("mv");
#endif
}*/
char *OS_mvstr();
long ramkv777_save(struct ramkv777 *kv)
{
    FILE *fp; long retval = -1; char fname[512],oldfname[512],cmd[512];
    sprintf(fname,"%s.tmp",kv->name);
    if ( (fp= fopen(fname,"wb")) != 0 )
    {
        if ( ramkv777_iterate(kv,fp,ramkv777_saveiterator) == 0 )
        {
            printf("save %ld to HDD\n",ftell(fp));
            retval = ftell(fp);
        }
        else printf("error saving item at %ld\n",ftell(fp));
        fclose(fp);
    } else printf("error creating(%s)\n",fname);
    if ( retval > 0 )
    {
        sprintf(oldfname,"%s.%u",kv->name,(uint32_t)time(NULL));
        sprintf(cmd,"%s %s %s",OS_mvstr(),kv->name,oldfname);
        if ( system(cmd) != 0 )
            printf("error issuing.(%s)\n",cmd);
        sprintf(cmd,"%s %s %s",OS_mvstr(),fname,kv->name);
        if ( system(cmd) != 0 )
            printf("error issuing.(%s)\n",cmd);
   }
    return(retval);
}

struct ramkv777 *ramkv777_init(int32_t kvind,char *name,int32_t keysize,int32_t threadsafe)
{
    struct ramkv777 *kv;
    printf("ramkv777_init.(%s)\n",name);
    kv = calloc(1,sizeof(*kv));
    strcpy(kv->name,name);
    kv->threadsafe = threadsafe, kv->keysize = keysize, kv->kvind = kvind;//, kv->dispflag = 1;
    portable_mutex_init(&kv->mutex);
    vupdate_sha256(kv->sha256.bytes,&kv->state,0,0);
    return(kv);
}

int32_t ramkv777_disp(struct ramkv777 *kv)
{
    struct ramkv777_item *item,*tmp; int32_t n = 0;
    printf("ramkv777_disp.(%s)\n",kv->name);
    if ( kv == 0 )
        return(0);
    ramkv777_lock(kv);
    HASH_ITER(hh,kv->table,item,tmp)
    {
        n++;
        printf("%llx: %llx\n",*(long long *)ramkv777_itemkey(item),*(long long *)ramkv777_itemvalue(kv,item));
    }
    ramkv777_unlock(kv);
    printf("ramkv777_disp.(%s) n.%d items\n",kv->name,n);
    return(n);
}

void ramkv777_free(struct ramkv777 *kv)
{
    struct ramkv777_item *ptr,*tmp;
    if ( kv != 0 )
    {
        HASH_ITER(hh,kv->table,ptr,tmp)
        {
            HASH_DEL(kv->table,ptr);
            free(ptr);
        }
        free(kv);
    }
}

int32_t ramkv777_clone(struct ramkv777 *clone,struct ramkv777 *kv)
{
    struct ramkv777_item *item,*tmp; int32_t n = 0;
    if ( kv != 0 )
    {
        HASH_ITER(hh,kv->table,item,tmp)
        {
            ramkv777_write(clone,item->keyvalue,ramkv777_itemvalue(kv,item),item->valuesize);
            n++;
        }
    }
    return(n);
}

struct ramkv777_item *ramkv777_itemptr(struct ramkv777 *kv,void *value)
{
    struct ramkv777_item *item = 0;
    if ( kv != 0 && value != 0 )
    {
        value = (void *)((long)value - (kv)->keysize);
        item = (void *)((long)value - ((long)item->keyvalue - (long)item));
    }
    return(item);
}



