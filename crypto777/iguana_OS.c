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

// iguana_OS has functions that invoke system calls. Whenever possible stdio and similar functions are use and most functions are fully portable and in this file. For things that require OS specific, the call is routed to iguana_OS_portable_*  Usually, all but one OS can be handled with the same code, so iguana_OS_portable.c has most of this shared logic and an #ifdef iguana_OS_nonportable.c

// time functions are treated separately due to the confusions even in unix

#include "OS_portable.h"
#include <sys/stat.h>
#ifndef MAP_FILE
#define MAP_FILE        0
#endif

void OS_randombytes(unsigned char *x,long xlen)
{
    OS_portable_randombytes(x,xlen);
}
           
static double _kb(double n) { return(n / 1024.); }
static double _mb(double n) { return(n / (1024.*1024.)); }
static double _gb(double n) { return(n / (1024.*1024.*1024.)); }

char *mbstr(char *str,double n)
{
	if ( n < 1024*1024*10 )
		sprintf(str,"%.3fkb",_kb(n));
	else if ( n < 1024*1024*1024 )
		sprintf(str,"%.1fMB",_mb(n));
	else
		sprintf(str,"%.2fGB",_gb(n));
	return(str);
}

long myallocated(uint8_t type,long change)
{
    static int64_t Total_allocated,HWM_allocated,Type_allocated[256];
    int32_t i; int64_t total = 0; char buf[2049],str[65];
    buf[0] = 0;
    if ( type == 0 && change <= 0 )
    {
        for (i=0; i<256; i++)
        {
            if ( Type_allocated[i] != 0 )
            {
                total += Type_allocated[i];
                if ( change == 0 )
                    sprintf(buf+strlen(buf),"(%c %s) ",i,mbstr(str,Type_allocated[i]));
            }
        }
        if ( change == 0 )
        {
            sprintf(buf + strlen(buf),"-> total %lld %s",(long long)total,mbstr(str,total));
            printf("%s\n",buf);
        }
    }
    else
    {
        Type_allocated[type] += change;
        Total_allocated += change;
        if ( Total_allocated > HWM_allocated )
        {
            printf("HWM allocated %ld %s\n",(long)Total_allocated,mbstr(str,Total_allocated));
            HWM_allocated = Total_allocated * 1.5;
        }
    }
    return(total);
}

void *mycalloc(uint8_t type,int32_t n,long itemsize)
{
    //static portable_mutex_t MEMmutex;
    struct allocitem *item; int64_t allocsize = ((uint64_t)n * itemsize);
    if ( type == 0 && n == 0 && itemsize == 0 )
    {
        //portable_mutex_init(&MEMmutex);
        myfree(mycalloc('t',1024,1024 * 32),1024*1024*32);
        return(0);
    }
    //portable_mutex_lock(&MEMmutex);
    myallocated(type,allocsize);
    while ( (item= calloc(1,sizeof(struct allocitem) + allocsize + 16)) == 0 )
    {
        char str[65];
        printf("mycalloc: need to wait for memory.(%d,%ld) %s to be available\n",n,itemsize,mbstr(str,allocsize));
        sleep(1);
    }
    //printf("calloc origptr.%p retptr.%p size.%ld\n",item,(void *)(long)item + sizeof(*item),allocsize);
    item->allocsize = (uint32_t)allocsize;
    item->type = type;
    //portable_mutex_unlock(&MEMmutex);
    return((void *)(long)item + sizeof(*item));
}

void *queueitem(char *str)
{
    struct queueitem *item; int32_t n,allocsize; char *data; uint8_t type = 'y';
    //portable_mutex_lock(&MEMmutex);
    n = (uint32_t)strlen(str) + 1;
    allocsize = (uint32_t)(sizeof(struct queueitem) + n);
    myallocated(type,allocsize);
    while ( (item= calloc(1,allocsize)) == 0 )
    {
        char str[65];
        printf("queueitem: need to wait for memory.(%d,%ld) %s to be available\n",n,(long)sizeof(*item),mbstr(str,allocsize));
        sleep(1);
    }
    item->allocsize = (uint32_t)allocsize;
    item->type = type;
    data = (void *)((uint64_t)item + sizeof(*item));
    memcpy(data,str,n);
    //printf("(%c) queueitem.%p itemdata.%p n.%d allocsize.%d\n",type,item,data,n,allocsize);
    //portable_mutex_unlock(&MEMmutex);
    return(data);
}

void _myfree(uint8_t type,int32_t origallocsize,void *origptr,int32_t allocsize)
{
    //portable_mutex_lock(&MEMmutex);
    if ( allocsize == origallocsize )
    {
        myallocated(type,-allocsize);
        // Type_allocated[type & 0xff] -= allocsize;
        // Total_allocated -= allocsize;
        //printf("myfree.%p size.%d %d type %x\n",origptr,allocsize,origallocsize,type);
        free(origptr);
    }
    else
    {
        printf("myfree size error %d vs %d at %p\n",allocsize,origallocsize,origptr);
        getchar();
    }
    //portable_mutex_unlock(&MEMmutex);
}

void myfree(void *_ptr,long allocsize)
{
    struct allocitem *item = (void *)((long)_ptr - sizeof(struct allocitem));
    _myfree(item->type,item->allocsize,item,(uint32_t)allocsize);
}

void free_queueitem(void *itemdata)
{
    struct queueitem *item = (void *)((long)itemdata - sizeof(struct queueitem));
    //printf("freeq item.%p itemdata.%p size.%d\n",item,itemdata,item->allocsize);
    _myfree(item->type,item->allocsize,item,item->allocsize);
}

void *myrealloc(uint8_t type,void *oldptr,long oldsize,long newsize)
{
    void *newptr;
    newptr = mycalloc(type,1,newsize);
    //printf("newptr.%p type.%c oldsize.%ld newsize.%ld\n",newptr,type,oldsize,newsize);
    if ( oldptr != 0 )
    {
        memcpy(newptr,oldptr,oldsize < newsize ? oldsize : newsize);
        myfree(oldptr,oldsize);
    }
    return(newptr);
}

static uint64_t _align16(uint64_t ptrval) { if ( (ptrval & 15) != 0 ) ptrval += 16 - (ptrval & 15); return(ptrval); }

void *myaligned_alloc(uint64_t allocsize)
{
    void *ptr,*realptr; uint64_t tmp;
    realptr = mycalloc('A',1,(long)(allocsize + 16 + sizeof(realptr)));
    tmp = _align16((long)realptr + sizeof(ptr));
    memcpy(&ptr,&tmp,sizeof(ptr));
    memcpy((void *)((long)ptr - sizeof(realptr)),&realptr,sizeof(realptr));
    //printf("aligned_alloc(%llu) realptr.%p -> ptr.%p, diff.%ld\n",(long long)allocsize,realptr,ptr,((long)ptr - (long)realptr));
    return(ptr);
}

int32_t myaligned_free(void *ptr,long size)
{
    void *realptr;
    long diff;
    if ( ((long)ptr & 0xf) != 0 )
    {
        printf("misaligned ptr.%p being aligned_free\n",ptr);
        return(-1);
    }
    memcpy(&realptr,(void *)((long)ptr - sizeof(realptr)),sizeof(realptr));
    diff = ((long)ptr - (long)realptr);
    if ( diff < (long)sizeof(ptr) || diff > 32 )
    {
        printf("ptr %p and realptr %p too far apart %ld\n",ptr,realptr,diff);
        return(-2);
    }
    //printf("aligned_free: ptr %p -> realptr %p %ld\n",ptr,realptr,diff);
    myfree(realptr,size + 16 + sizeof(realptr));
    return(0);
}

void lock_queue(queue_t *queue)
{
    if ( queue->initflag == 0 )
    {
        portable_mutex_init(&queue->mutex);
        queue->initflag = 1;
    }
	portable_mutex_lock(&queue->mutex);
}

void queue_enqueue(char *name,queue_t *queue,struct queueitem *origitem,int32_t offsetflag)
{
    struct queueitem *item;
    if ( queue->name[0] == 0 && name != 0 && name[0] != 0 )
        strcpy(queue->name,name);//,sizeof(queue->name));
    if ( origitem == 0 )
    {
        printf("FATAL type error: queueing empty value\n");//, getchar();
        return;
    }
    lock_queue(queue);
    item = (struct queueitem *)((long)origitem - offsetflag*sizeof(struct queueitem));
    DL_APPEND(queue->list,item);
    portable_mutex_unlock(&queue->mutex);
    //printf("queue_enqueue name.(%s) origitem.%p append.%p list.%p\n",name,origitem,item,queue->list);
}

void *queue_dequeue(queue_t *queue,int32_t offsetflag)
{
    struct queueitem *item = 0;
    lock_queue(queue);
    if ( queue->list != 0 )
    {
        item = queue->list;
        DL_DELETE(queue->list,item);
        //printf("queue_dequeue name.(%s) dequeue.%p list.%p\n",queue->name,item,queue->list);
    }
	portable_mutex_unlock(&queue->mutex);
    if ( item != 0 && offsetflag != 0 )
        return((void *)((long)item + sizeof(struct queueitem)));
    else return(item);
}

void *queue_delete(queue_t *queue,struct queueitem *copy,int32_t copysize,int32_t freeitem)
{
    struct queueitem *item = 0;
    lock_queue(queue);
    if ( queue->list != 0 )
    {
        DL_FOREACH(queue->list,item)
        {
            if ( item == copy || memcmp((void *)((long)item + sizeof(struct queueitem)),(void *)((long)item + sizeof(struct queueitem)),copysize) == 0 )
            {
                DL_DELETE(queue->list,item);
                portable_mutex_unlock(&queue->mutex);
                printf("name.(%s) deleted item.%p list.%p\n",queue->name,item,queue->list);
                if ( freeitem != 0 )
                    myfree(item,copysize);
                return(item);
            }
        }
    }
	portable_mutex_unlock(&queue->mutex);
    return(0);
}

void *queue_free(queue_t *queue)
{
    struct queueitem *item = 0;
    lock_queue(queue);
    if ( queue->list != 0 )
    {
        DL_FOREACH(queue->list,item)
        {
            DL_DELETE(queue->list,item);
            myfree(item,sizeof(struct queueitem));
        }
        //printf("name.(%s) dequeue.%p list.%p\n",queue->name,item,queue->list);
    }
	portable_mutex_unlock(&queue->mutex);
    return(0);
}

void *queue_clone(queue_t *clone,queue_t *queue,int32_t size)
{
    struct queueitem *ptr,*item = 0;
    lock_queue(queue);
    if ( queue->list != 0 )
    {
        DL_FOREACH(queue->list,item)
        {
            ptr = mycalloc('c',1,sizeof(*ptr));
            memcpy(ptr,item,size);
            queue_enqueue(queue->name,clone,ptr,0);
        }
        //printf("name.(%s) dequeue.%p list.%p\n",queue->name,item,queue->list);
    }
	portable_mutex_unlock(&queue->mutex);
    return(0);
}

int32_t queue_size(queue_t *queue)
{
    int32_t count = 0;
    struct queueitem *tmp;
    lock_queue(queue);
    DL_COUNT(queue->list,tmp,count);
    portable_mutex_unlock(&queue->mutex);
	return count;
}

void iguana_memreset(struct OS_memspace *mem)
{
    mem->used = 0;
#ifdef IGUANA_PEERALLOC
    mem->availptrs = mem->outofptrs = mem->numptrs = 0;
    memset(mem->ptrs,0,sizeof(mem->ptrs));
    memset(mem->maxsizes,0,sizeof(mem->maxsizes));
    memset(mem->allocsizes,0,sizeof(mem->allocsizes));
#endif
    if ( mem->threadsafe != 0 )
        portable_mutex_init(&mem->mutex);
}

void iguana_mempurge(struct OS_memspace *mem)
{
    if ( mem->allocated != 0 && mem->ptr != 0 && mem->totalsize > 0 )
        myfree(mem->ptr,mem->totalsize), mem->ptr = 0;
    iguana_memreset(mem);
    mem->totalsize = 0;
}

void *iguana_meminit(struct OS_memspace *mem,char *name,void *ptr,int64_t totalsize,int32_t threadsafe)
{
    strcpy(mem->name,name);
    if ( ptr == 0 )
    {
        if ( mem->ptr != 0 && mem->totalsize < totalsize )
        {
            iguana_mempurge(mem);
            mem->totalsize = 0;
            //printf("memptr.%p totalsize.%ld vs totalsize.%ld\n",mem->ptr,(long)mem->totalsize,(long)totalsize);
        } //else printf("mem->ptr.%p mem->totalsize %ld\n",mem->ptr,(long)mem->totalsize);
        if ( mem->ptr == 0 )
        {
            //static long alloc;
            //alloc += totalsize;
            //char str[65]; printf("iguana_meminit alloc %s\n",mbstr(str,alloc));
            if ( (mem->ptr= mycalloc('d',1,totalsize)) == 0 )
            {
                printf("iguana_meminit: cant get %d bytes\n",(int32_t)totalsize);
                exit(-1);
                return(0);
            }
            mem->totalsize = totalsize;
        } //else printf("memptr.%p\n",mem->ptr);
        //printf("meminit.(%s) %d vs %ld\n",mem->name,(int32_t)totalsize,(long)mem->totalsize);
        mem->allocated = 1;
    }
    else
    {
        iguana_mempurge(mem);
        mem->ptr = ptr;
        mem->totalsize = totalsize;
    }
    mem->threadsafe = threadsafe;
    iguana_memreset(mem);
    if ( mem->totalsize == 0 )
        printf("meminit.%s ILLEGAL STATE null size\n",mem->name), getchar();
    return(mem->ptr);
}

int64_t iguana_memallocated(struct OS_memspace *mem)
{
    int64_t avail = (mem->totalsize - mem->used);
#ifdef IGUANA_PEERALLOC
    int32_t i;
    for (i=0; i<mem->numptrs; i++)
        if ( mem->allocsizes[i] == 0 )
            avail += mem->maxsizes[i];
#endif
    return(avail);
}

void *iguana_memalloc(struct OS_memspace *mem,long size,int32_t clearflag)
{
    int32_t modval; void *ptr = 0;
    //printf("iguana_memalloc.%s size.%ld used.%llu of %llu, numptrs.%d avail.%d %lld\n",mem->name,size,(long long)mem->used,(long long)mem->totalsize,mem->numptrs,mem->availptrs,(long long)iguana_memallocated(mem));
    //if ( mem->threadsafe != 0 )
    //    portable_mutex_lock(&mem->mutex);
#ifdef IGUANA_PEERALLOC
    if ( mem->availptrs == mem->numptrs && mem->used > (mem->totalsize >> 1) )
        iguana_memreset(mem);
#endif
    if ( (mem->used + size) <= mem->totalsize )
    {
        ptr = (void *)((uint64_t)mem->ptr + (uint64_t)mem->used);
        mem->used += size;
        if ( size*clearflag != 0 )
            memset(ptr,0,size);
        if ( mem->alignflag != 0 )
        {
            if ( (modval= (mem->used % mem->alignflag)) != 0 )
                mem->used += mem->alignflag - modval;
        }
#ifdef IGUANA_PEERALLOC
        if ( mem->numptrs < sizeof(mem->ptrs)/sizeof(*mem->ptrs) )
        {
            mem->allocsizes[mem->numptrs] = mem->maxsizes[mem->numptrs] = (int32_t)size;
            mem->ptrs[mem->numptrs++] = ptr;
        }
        else
        {
            mem->outofptrs++;
            printf("iguana_memalloc: numptrs.%d outofptrs.%d\n",mem->numptrs,mem->outofptrs);
        }
#endif
        //printf(">>>>>>>>> USED.%s alloc %ld used %ld alloc.%ld -> %s %p\n",mem->name,size,(long)mem->used,(long)mem->totalsize,mem->name,ptr);
    } else printf("error memalloc mem.%p %s alloc %ld used %ld totalsize.%ld -> %s %p\n",mem,mem->name,size,(long)mem->used,(long)mem->totalsize,mem->name,ptr), getchar();//exit(-1);
    //if ( mem->threadsafe != 0 )
    //    portable_mutex_unlock(&mem->mutex);
    return(ptr);
}

int64_t iguana_memfree(struct OS_memspace *mem,void *ptr,int32_t size)
{
#ifdef IGUANA_PEERALLOC
    int32_t i; int64_t avail = -1;
    if ( mem->threadsafe != 0 )
        portable_mutex_lock(&mem->mutex);
    for (i=0; i<mem->numptrs; i++)
    {
        if ( ptr == mem->ptrs[i] )
        {
            if ( mem->allocsizes[i] == size )
            {
                mem->availptrs++;
                mem->allocsizes[i] = 0;
                avail = (mem->totalsize - mem->used);
                //printf("avail %llu\n",(long long)avail);
            } else printf("iguana_memfree.%s: mismatched size %d for ptr.%p %d\n",mem->name,size,ptr,mem->allocsizes[i]);
            if ( mem->threadsafe != 0 )
                portable_mutex_unlock(&mem->mutex);
            return(avail);
        }
    }
    if ( mem->threadsafe != 0 )
        portable_mutex_unlock(&mem->mutex);
    printf("iguana_memfree: cant find ptr.%p %d\n",ptr,size);
    return(avail);
#else
    printf("iguana_free not supported without #define IGUANA_PEERALLOC\n");
    return(0);
#endif
}

int32_t OS_truncate(char *fname,long filesize)
{
    return(OS_portable_truncate(fname,filesize));
}

char *OS_compatible_path(char *str)
{
    return(OS_portable_path(str));
}

int32_t OS_renamefile(char *fname,char *newfname)
{
    return(OS_portable_renamefile(fname,newfname));
}

int32_t OS_removefile(char *fname,int32_t scrubflag)
{
    FILE *fp; long i,fpos; char tmp[512];
    strcpy(tmp,fname);
    OS_compatible_path(tmp);
    if ( (fp= fopen(tmp,"rb+")) != 0 )
    {
        //printf("delete(%s)\n",fname);
        if ( scrubflag != 0 )
        {
            fseek(fp,0,SEEK_END);
            fpos = ftell(fp);
            rewind(fp);
            for (i=0; i<fpos; i++)
                fputc(0xff,fp);
            fflush(fp);
        }
        fclose(fp);
        if ( (fp= fopen(tmp,"wb")) != 0 )
            fclose(fp);
        return(OS_portable_removefile(fname));
    }
    return(0);
}

void OS_ensure_directory(char *dirname)
{
    FILE *fp; int32_t retval; char fname[512];
    if ( OS_removefile(dirname,0) < 0 )
    {
        sprintf(fname,"tmp/%d",rand());
        OS_renamefile(dirname,fname);
    }
    sprintf(fname,"%s/.tmpmarker",dirname);
    if ( (fp= fopen(OS_compatible_path(fname),"rb")) == 0 )
    {
        if ( (fp= fopen(OS_compatible_path(dirname),"rb")) == 0 )
        {
            retval = mkdir(dirname
#ifndef _WIN32
                           ,511
#endif
                           );
            printf("mkdir.(%s) retval.%d errno.%d %s\n",dirname,retval,errno,strerror(errno));
        } else fclose(fp), printf("dirname.(%s) exists\n",dirname);
        if ( (fp= fopen(fname,"wb")) != 0 )
            fclose(fp), printf("created.(%s)\n",fname);
        else printf("cant create.(%s) errno.%d %s\n",fname,errno,strerror(errno));
    } else fclose(fp), printf("%s exists\n",fname);
}

uint64_t OS_filesize(char *fname)
{
    FILE *fp; uint64_t fsize = 0;
    if ( (fp= fopen(fname,"rb")) != 0 )
    {
        fseek(fp,0,SEEK_END);
        fsize = ftell(fp);
        fclose(fp);
    }
    return(fsize);
}

int32_t OS_compare_files(char *fname,char *fname2)
{
    int32_t offset,errs = 0;
    long len,len2;
    char buf[8192],buf2[8192];
    FILE *fp,*fp2;
    if ( (fp= fopen(OS_compatible_path(fname),"rb")) != 0 )
    {
        if ( (fp2= fopen(OS_compatible_path(fname2),"rb")) != 0 )
        {
            while ( (len= fread(buf,1,sizeof(buf),fp)) > 0 && (len2= fread(buf2,1,sizeof(buf2),fp2)) == len )
                if ( (offset= memcmp(buf,buf2,len)) != 0 )
                    printf("compare error at offset.%d: (%s) src.%ld vs. (%s) dest.%ld\n",offset,fname,ftell(fp),fname2,ftell(fp2)), errs++;
            fclose(fp2);
        }
        fclose(fp);
    }
    return(errs);
}

int64_t OS_copyfile(char *src,char *dest,int32_t cmpflag)
{
    int64_t allocsize,len = -1;
    char *buf;
    FILE *srcfp,*destfp;
    if ( (srcfp= fopen(OS_compatible_path(src),"rb")) != 0 )
    {
        if ( (destfp= fopen(OS_compatible_path(dest),"wb")) != 0 )
        {
            allocsize = 1024 * 1024 * 128L;
            buf = mycalloc('F',1,allocsize);
            while ( (len= fread(buf,1,allocsize,srcfp)) > 0 )
                if ( (long)fwrite(buf,1,len,destfp) != len )
                    printf("write error at (%s) src.%ld vs. (%s) dest.%ld\n",src,ftell(srcfp),dest,ftell(destfp));
            len = ftell(destfp);
            fclose(destfp);
            myfree(buf,allocsize);
        }
        fclose(srcfp);
    }
    if ( len < 0 || (cmpflag != 0 && OS_compare_files(src,dest) != 0) )
        printf("Error copying files (%s) -> (%s)\n",src,dest), len = -1;
    return(len);
}

int32_t OS_releasemap(void *ptr,uint64_t filesize)
{
	int32_t retval;
    if ( ptr == 0 )
	{
		printf("release_map_file: null ptr\n");
		return(-1);
	}
	retval = munmap(ptr,filesize);
	if ( retval != 0 )
		printf("release_map_file: munmap error %p %llu: err %d\n",ptr,(long long)filesize,retval);
	return(retval);
}

void _OS_closemap(struct OS_mappedptr *mp)
{
	if ( mp->actually_allocated != 0 && mp->fileptr != 0 )
        myaligned_free(mp->fileptr,mp->allocsize);
	else if ( mp->fileptr != 0 )
		OS_releasemap(mp->fileptr,mp->allocsize);
	mp->fileptr = 0;
    mp->closetime = (uint32_t)time(NULL);
    mp->opentime = 0;
}

void OS_closemap(struct OS_mappedptr *mp)
{
	struct OS_mappedptr tmp;
	tmp = *mp;
	_OS_closemap(mp);
	memset(mp,0,sizeof(*mp));
	mp->actually_allocated = tmp.actually_allocated;
	mp->allocsize = tmp.allocsize;
	mp->rwflag = tmp.rwflag;
	strcpy(mp->fname,tmp.fname);
}

long OS_ensurefilesize(char *fname,long filesize,int32_t truncateflag)
{
    FILE *fp;
    char *zeroes;
    long i,n,allocsize = 0;
    //printf("ensure_filesize.(%s) %ld %s | ",fname,filesize,mbstr(filesize));
    if ( (fp= fopen(OS_compatible_path(fname),"rb")) != 0 )
    {
        fseek(fp,0,SEEK_END);
        allocsize = ftell(fp);
        fclose(fp);
        //printf("(%s) exists size.%ld\n",fname,allocsize);
    }
    else
    {
        //printf("try to create.(%s)\n",fname);
        if ( (fp= fopen(OS_compatible_path(fname),"wb")) != 0 )
            fclose(fp);
    }
    if ( allocsize < filesize )
    {
        //printf("filesize.%ld is less than %ld\n",filesize,allocsize);
        if ( (fp= fopen(OS_compatible_path(fname),"ab")) != 0 )
        {
			zeroes = myaligned_alloc(16L*1024*1024);
            memset(zeroes,0,16*1024*1024);
            n = filesize - allocsize;
            while ( n > 16*1024*1024 )
            {
                fwrite(zeroes,1,16*1024*1024,fp);
                n -= 16*1024*1024;
                fprintf(stderr,"+");
            }
            for (i=0; i<n; i++)
                fputc(0,fp);
            fclose(fp);
			myaligned_free(zeroes,16L*1024*1024);
        }
        return(filesize);
    }
    else if ( allocsize*truncateflag > filesize )
    {
        OS_truncate(fname,filesize);
        return(filesize);
    }
    else return(allocsize);
}

int32_t OS_openmap(struct OS_mappedptr *mp)
{
	uint64_t allocsize = mp->allocsize;
    if ( mp->actually_allocated != 0 )
	{
		if ( mp->fileptr == 0 )
			mp->fileptr = myaligned_alloc(mp->allocsize);
		else memset(mp->fileptr,0,mp->allocsize);
		return(0);
	}
	else
	{
		if ( mp->fileptr != 0 )
		{
			//printf("opening already open mappedptr, pending %p\n",mp->pending);
			OS_closemap(mp);
		}
        mp->allocsize = allocsize;
		// printf("calling map_file with expected %ld\n",mp->allocsize);
		mp->fileptr = OS_mapfile(mp->fname,&mp->allocsize,mp->rwflag);
		if ( mp->fileptr == 0 || mp->allocsize != allocsize )
		{
			//printf("error mapping(%s) ptr %p mapped %ld vs allocsize %ld\n",mp->fname,mp->fileptr,mp->allocsize,allocsize);
			return(-1);
		}
        mp->closetime = 0;
        mp->opentime = (uint32_t)time(NULL);
	}
	return(0);
}

void *OS_mappedptr(void **ptrp,struct OS_mappedptr *mp,uint64_t allocsize,int32_t rwflag,char *fname)
{
	uint64_t filesize;
	mp->actually_allocated = 0;//!os_supports_mappedfiles();
    if ( fname != 0 )
	{
		if ( strcmp(mp->fname,fname) == 0 )
		{
			if ( mp->fileptr != 0 )
			{
				OS_releasemap(mp->fileptr,mp->allocsize);
				mp->fileptr = 0;
			}
			OS_openmap(mp);
			if ( ptrp != 0 )
				(*ptrp) = mp->fileptr;
			return(mp->fileptr);
		}
		strcpy(mp->fname,fname);
	}
	else mp->actually_allocated = 1;
	mp->rwflag = rwflag;
	mp->allocsize = allocsize;
    if ( rwflag != 0 && mp->actually_allocated == 0 && allocsize != 0 )
        allocsize = OS_ensurefilesize(fname,allocsize,0);
	if ( OS_openmap(mp) != 0 )
	{
        char str[65];
        //printf("init_mappedptr %s.rwflag.%d | ",fname,rwflag);
        if ( allocsize != 0 )
			printf("error mapping(%s) rwflag.%d ptr %p mapped %llu vs allocsize %llu %s\n",fname,rwflag,mp->fileptr,(long long)mp->allocsize,(long long)allocsize,mbstr(str,allocsize));
        else allocsize = mp->allocsize;
		if ( rwflag != 0 && allocsize != mp->allocsize )
		{
			filesize = mp->allocsize;
			if  ( mp->fileptr != 0 )
				OS_releasemap(mp->fileptr,mp->allocsize);
			mp->allocsize = allocsize;
			mp->changedsize = (allocsize - filesize);
			OS_openmap(mp);
			if ( mp->fileptr == 0 || mp->allocsize != allocsize )
            {
				printf("SECOND error mapping(%s) ptr %p mapped %llu vs allocsize %llu\n",fname,mp->fileptr,(long long)mp->allocsize,(long long)allocsize);
                exit(-1);
            }
		}
	}
	if ( ptrp != 0 )
		(*ptrp) = mp->fileptr;
    return(mp->fileptr);
}

void *OS_filealloc(struct OS_mappedptr *M,char *fname,struct OS_memspace *mem,long size)
{
    //printf("mem->used %ld size.%ld | size.%ld\n",mem->used,size,mem->size);
    //printf("filemalloc.(%s) new space.%ld %s\n",fname,mem->size,mbstr(size));
    memset(M,0,sizeof(*M));
    mem->totalsize = size;
    if ( OS_mappedptr(0,M,mem->totalsize,1,fname) == 0 )
    {
        printf("couldnt create mapped file.(%s)\n",fname);
        exit(-1);
    }
    mem->ptr = M->fileptr;
    mem->used = 0;
    return(M->fileptr);
}

void *OS_loadfile(char *fname,char **bufp,int64_t *lenp,int64_t *allocsizep)
{
    FILE *fp;
    int64_t  filesize,buflen = *allocsizep;
    char *buf = *bufp;
    *lenp = 0;
    if ( (fp= fopen(OS_compatible_path(fname),"rb")) != 0 )
    {
        fseek(fp,0,SEEK_END);
        filesize = ftell(fp);
        if ( filesize == 0 )
        {
            fclose(fp);
            *lenp = 0;
            return(0);
        }
        if ( filesize > buflen-1 )
        {
            *allocsizep = filesize+1;
            *bufp = buf = realloc(buf,(long)*allocsizep);
        }
        rewind(fp);
        if ( buf == 0 )
            printf("Null buf ???\n");
        else
        {
            if ( fread(buf,1,(long)filesize,fp) != (unsigned long)filesize )
                printf("error reading filesize.%ld\n",(long)filesize);
            buf[filesize] = 0;
        }
        fclose(fp);
        *lenp = filesize;
    }
    return(buf);
}

void *OS_filestr(int64_t *allocsizep,char *fname)
{
    int64_t filesize = 0; char *buf = 0;
    *allocsizep = 0;
    return(OS_loadfile(fname,&buf,&filesize,allocsizep));
}

// following functions cant be fully implemented in one or more OS
void *OS_mapfile(char *fname,long *filesizep,int32_t enablewrite) // win and pnacl dont have mmap64
{
	return(OS_portable_mapfile(fname,filesizep,enablewrite));
}

int32_t OS_syncmap(struct OS_mappedptr *mp,long len) // pnacl doesnt implement sync
{
    return(OS_portable_syncmap(mp,len));
}

void *OS_tmpalloc(char *dirname,char *name,struct OS_memspace *mem,long origsize) // no syncmap no tmpalloc
{
    return(OS_portable_tmpalloc(dirname,name,mem,origsize));
}

#include <curl/curl.h>
void OS_init()
{
    curl_global_init(CURL_GLOBAL_ALL); //init the curl session
    SaM_PrepareIndices();
    return(OS_portable_init());
}