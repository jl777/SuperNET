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

#include "iguana777.h"
#include <sys/stat.h>
#ifndef MAP_FILE
#define MAP_FILE        0
#endif

int32_t conv_date(int32_t *secondsp,char *buf);

uint32_t OS_conv_datenum(int32_t datenum,int32_t hour,int32_t minute,int32_t second) // datenum+H:M:S -> unix time
{
#ifdef __PNACL
    PostMessage("timegm is not implemented\n");
    return(0);
#else
    struct tm t;
    memset(&t,0,sizeof(t));
    t.tm_year = (datenum / 10000) - 1900, t.tm_mon = ((datenum / 100) % 100) - 1, t.tm_mday = (datenum % 100);
    t.tm_hour = hour, t.tm_min = minute, t.tm_sec = second;
    return((uint32_t)timegm(&t));
#endif
}

int32_t OS_conv_unixtime(int32_t *secondsp,time_t timestamp) // gmtime -> datenum + number of seconds
{
    struct tm t; int32_t datenum; uint32_t checktime; char buf[64];
    t = *gmtime(&timestamp);
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ",&t); //printf("%s\n",buf);
    datenum = conv_date(secondsp,buf);
    if ( (checktime= OS_conv_datenum(datenum,*secondsp/3600,(*secondsp%3600)/60,*secondsp%60)) != timestamp )
    {
        printf("error: timestamp.%lu -> (%d + %d) -> %u\n",timestamp,datenum,*secondsp,checktime);
        return(-1);
    }
    return(datenum);
}

char *OS_mvstr()
{
#ifdef __WIN32
    return("rename");
#else
    return("mv");
#endif
}

char *OS_rmstr() { return("rm"); }

int32_t os_supports_mappedfiles() { return(1); }

int32_t portable_truncate(char *fname,long filesize) { return(truncate(fname,filesize)); }

char *iguana_compatible_path(char *str)
{
    return(str);
}

void ensure_directory(char *dirname)
{
    FILE *fp; int32_t retval; char fname[512];
    iguana_removefile(dirname,0);
    sprintf(fname,"%s/.tmpmarker",dirname);
    if ( (fp= fopen(iguana_compatible_path(fname),"rb")) == 0 )
    {
        if ( (fp= fopen(iguana_compatible_path(dirname),"rb")) == 0 )
        {
            retval = mkdir(dirname,511);
            printf("mkdir.(%s) retval.%d errno.%d %s\n",dirname,retval,errno,strerror(errno));
        } else fclose(fp), printf("dirname.(%s) exists\n",dirname);
        if ( (fp= fopen(fname,"wb")) != 0 )
            fclose(fp), printf("created.(%s)\n",fname);
        else printf("cant create.(%s) errno.%d %s\n",fname,errno,strerror(errno));
    } else fclose(fp), printf("%s exists\n",fname);
}

int32_t iguana_renamefile(char *fname,char *newfname)
{
    char cmd[1024];
    sprintf(cmd,"%s %s %s",OS_mvstr(),fname,newfname);
    return(system(cmd));
}

int32_t iguana_removefile(char *fname,int32_t scrubflag)
{
    FILE *fp;
    char cmdstr[1024];
    long i,fpos;
    if ( (fp= fopen(iguana_compatible_path(fname),"rb+")) != 0 )
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
        sprintf(cmdstr,"%s %s",OS_rmstr(),fname);
        if ( system(iguana_compatible_path(cmdstr)) != 0 )
            printf("error deleting file.(%s)\n",cmdstr);
        else return(1);
    }
    return(0);
}

uint64_t iguana_filesize(char *fname)
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

int32_t iguana_compare_files(char *fname,char *fname2)
{
    int32_t offset,errs = 0;
    long len,len2;
    char buf[8192],buf2[8192];
    FILE *fp,*fp2;
    if ( (fp= fopen(iguana_compatible_path(fname),"rb")) != 0 )
    {
        if ( (fp2= fopen(iguana_compatible_path(fname2),"rb")) != 0 )
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

int64_t iguana_copyfile(char *src,char *dest,int32_t cmpflag)
{
    int64_t allocsize,len = -1;
    char *buf;
    FILE *srcfp,*destfp;
    if ( (srcfp= fopen(iguana_compatible_path(src),"rb")) != 0 )
    {
        if ( (destfp= fopen(iguana_compatible_path(dest),"wb")) != 0 )
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
    if ( len < 0 || (cmpflag != 0 && iguana_compare_files(src,dest) != 0) )
        printf("Error copying files (%s) -> (%s)\n",src,dest), len = -1;
    return(len);
}

void *map_file(char *fname,long *filesizep,int32_t enablewrite)
{
	//void *mmap64(void *addr,size_t len,int32_t prot,int32_t flags,int32_t fildes,off_t off);
	int32_t fd,rwflags,flags = MAP_FILE|MAP_SHARED;
	uint64_t filesize;
    void *ptr = 0;
	*filesizep = 0;
	if ( enablewrite != 0 )
		fd = open(fname,O_RDWR);
	else fd = open(fname,O_RDONLY);
	if ( fd < 0 )
	{
		printf("map_file: error opening enablewrite.%d %s\n",enablewrite,fname);
        return(0);
	}
    if ( *filesizep == 0 )
        filesize = (uint64_t)lseek(fd,0,SEEK_END);
    else filesize = *filesizep;
	rwflags = PROT_READ;
	if ( enablewrite != 0 )
		rwflags |= PROT_WRITE;
    //#if __i386__
	ptr = mmap(0,filesize,rwflags,flags,fd,0);
    //#else
	//ptr = mmap64(0,filesize,rwflags,flags,fd,0);
    //#endif
	close(fd);
    if ( ptr == 0 || ptr == MAP_FAILED )
	{
		printf("map_file.write%d: mapping %s failed? mp %p\n",enablewrite,fname,ptr);
		return(0);
	}
	*filesizep = filesize;
	return(ptr);
}

int32_t iguana_releasemap(void *ptr,uint64_t filesize)
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

void _iguana_closemap(struct iguana_mappedptr *mp)
{
	if ( mp->actually_allocated != 0 && mp->fileptr != 0 )
        myaligned_free(mp->fileptr,mp->allocsize);
	else if ( mp->fileptr != 0 )
		iguana_releasemap(mp->fileptr,mp->allocsize);
	mp->fileptr = 0;
    mp->closetime = (uint32_t)time(NULL);
    mp->opentime = 0;
}

void iguana_closemap(struct iguana_mappedptr *mp)
{
	struct iguana_mappedptr tmp;
	tmp = *mp;
	_iguana_closemap(mp);
	memset(mp,0,sizeof(*mp));
	mp->actually_allocated = tmp.actually_allocated;
	mp->allocsize = tmp.allocsize;
	mp->rwflag = tmp.rwflag;
	strcpy(mp->fname,tmp.fname);
}

int32_t iguana_syncmap(struct iguana_mappedptr *mp,long len)
{
    //static long Sync_total;
	int32_t err = -1;
	if ( mp->actually_allocated != 0 )
		return(0);
    if ( mp->fileptr != 0 && mp->dirty != 0 )
    {
        if ( len == 0 )
            len = mp->allocsize;
        err = msync(mp->fileptr,len,MS_SYNC);
        if ( err != 0 )
            printf("sync (%s) len %llu, err %d errno.%d\n",mp->fname,(long long)len,err,errno);
        //Sync_total += len;
        mp->dirty = 0;
    }
	return(err);
}

long iguana_ensurefilesize(char *fname,long filesize,int32_t truncateflag)
{
    FILE *fp;
    char *zeroes;
    long i,n,allocsize = 0;
    //printf("ensure_filesize.(%s) %ld %s | ",fname,filesize,mbstr(filesize));
    if ( (fp= fopen(iguana_compatible_path(fname),"rb")) != 0 )
    {
        fseek(fp,0,SEEK_END);
        allocsize = ftell(fp);
        fclose(fp);
        //printf("(%s) exists size.%ld\n",fname,allocsize);
    }
    else
    {
        //printf("try to create.(%s)\n",fname);
        if ( (fp= fopen(iguana_compatible_path(fname),"wb")) != 0 )
            fclose(fp);
    }
    if ( allocsize < filesize )
    {
        //printf("filesize.%ld is less than %ld\n",filesize,allocsize);
        if ( (fp= fopen(iguana_compatible_path(fname),"ab")) != 0 )
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
        portable_truncate(fname,filesize);
        return(filesize);
    }
    else return(allocsize);
}

int32_t iguana_openmap(struct iguana_mappedptr *mp)
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
			iguana_closemap(mp);
		}
        mp->allocsize = allocsize;
		// printf("calling map_file with expected %ld\n",mp->allocsize);
		mp->fileptr = map_file(mp->fname,&mp->allocsize,mp->rwflag);
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

void *iguana_mappedptr(void **ptrp,struct iguana_mappedptr *mp,uint64_t allocsize,int32_t rwflag,char *fname)
{
	uint64_t filesize;
	mp->actually_allocated = !os_supports_mappedfiles();
    if ( fname != 0 )
	{
		if ( strcmp(mp->fname,fname) == 0 )
		{
			if ( mp->fileptr != 0 )
			{
				iguana_releasemap(mp->fileptr,mp->allocsize);
				mp->fileptr = 0;
			}
			iguana_openmap(mp);
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
        allocsize = iguana_ensurefilesize(fname,allocsize,0);
	if ( iguana_openmap(mp) != 0 )
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
				iguana_releasemap(mp->fileptr,mp->allocsize);
			mp->allocsize = allocsize;
			mp->changedsize = (allocsize - filesize);
			iguana_openmap(mp);
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

//int64_t iguana_packetsallocated(struct iguana_info *coin) { return(coin->R.packetsallocated - coin->R.packetsfreed); };

void *filealloc(struct iguana_mappedptr *M,char *fname,struct iguana_memspace *mem,long size)
{
    //printf("mem->used %ld size.%ld | size.%ld\n",mem->used,size,mem->size);
    //printf("filemalloc.(%s) new space.%ld %s\n",fname,mem->size,mbstr(size));
    memset(M,0,sizeof(*M));
    mem->totalsize = size;
    if ( iguana_mappedptr(0,M,mem->totalsize,1,fname) == 0 )
    {
        printf("couldnt create mapped file.(%s)\n",fname);
        exit(-1);
    }
    mem->ptr = M->fileptr;
    mem->used = 0;
    return(M->fileptr);
}

void *iguana_tmpalloc(struct iguana_info *coin,char *name,struct iguana_memspace *mem,long origsize)
{
    char fname[1024]; void *ptr; long size;
#ifdef __PNACL
    return(mycalloc('T',1,origsize));
#endif
    //portable_mutex_lock(&mem->mutex);
    if ( origsize != 0 && (mem->M.fileptr == 0 || (mem->used + origsize) > mem->totalsize) )
    {
        coin->TMPallocated += origsize;
        memset(&mem->M,0,sizeof(mem->M));
        sprintf(fname,"tmp/%s/%s.%d",coin->symbol,name,mem->counter), iguana_compatible_path(fname);
        mem->counter++;
        if ( mem->totalsize == 0 )
        {
            //if ( strcmp(name,"recv") == 0 )
            //    mem->size = IGUANA_RSPACE_SIZE * ((strcmp(coin->symbol,"BTC") == 0) ? 16 : 1);
            // else
#ifdef IGUANA_MAPHASHTABLES
            mem->totalsize = (1024 * 1024 * 128);
#else
            mem->size = (1024 * 1024 * 16);
#endif
        }
        //if ( coin->R.RSPACE.size == 0 )
        //    coin->R.RSPACE.size = mem->size;
        if ( mem->totalsize > origsize )
            size = mem->totalsize;
        else size = origsize;
        fprintf(stderr,"filealloc.(%s) -> ",fname);
        if ( filealloc(&mem->M,fname,mem,size) == 0 )
        {
            printf("couldnt map tmpfile %s\n",fname);
            return(0);
        }
        fprintf(stderr,"created\n");
    }
    ptr = iguana_memalloc(mem,origsize,1);
    //portable_mutex_unlock(&mem->mutex);
    return(ptr);
}

#ifdef oldway
void *iguana_kvfixiterator(struct iguana_info *coin,struct iguanakv *kv,struct iguana_kvitem *item,uint64_t args,void *key,void *value,int32_t valuesize)
{
    int64_t offset = (int64_t)args;
    if ( args != 0 && (kv->flags & IGUANA_ITEMIND_DATA) != 0 )
    {
        item->hh.key = (void *)((uint64_t)item->hh.key + (int64_t)offset);
        //printf("iguana_kvfixiterator rawind.%-5d: (%s)\n",item->rawind,bits256_str(*(bits256 *)item->hh.key));
    }
    return(0);
}

void *_iguana_kvensure(struct iguana_info *coin,int32_t rwflag,int32_t *maxindp,char *name,char *fname,double mult,int32_t incr,uint32_t ind,struct iguana_mappedptr *M,int32_t HDDvaluesize)
{
    long needed,prevsize = 0;
    needed = (ind + 2) * HDDvaluesize;
    //printf("ensure.%s ind.%d needed.%ld origptr.%p\n",kv->name,ind,needed,origptr);
    if ( needed > M->allocsize )
    {
        needed = (((needed * mult) + incr * HDDvaluesize) / HDDvaluesize) * HDDvaluesize;
        printf("REMAP.%s %llu -> %ld [%ld] (%s) (ind.%d mult.%f incr.%d size.%d\n",name,(long long)M->allocsize,needed,(long)(needed - M->allocsize)/HDDvaluesize,fname,ind,mult,incr,HDDvaluesize);
        if ( M->fileptr != 0 )
        {
            iguana_syncmap(M,0);
            iguana_releasemap(M->fileptr,M->allocsize);
            M->fileptr = 0, prevsize = M->allocsize;
            M->allocsize = 0;
        }
        needed = iguana_ensurefilesize(fname,needed,0);
    }
    if ( M->fileptr == 0 )
    {
        if ( iguana_mappedptr(0,M,0,rwflag,fname) != 0 )
        {
            if ( 1 && prevsize > M->allocsize )
                memset((void *)((uint64_t)M->fileptr + prevsize),0,(M->allocsize - prevsize));
            printf("%p %s maxitems.%llu (MEMsize.%ld / itemsize.%d) prevsize.%ld needed.%ld\n",M->fileptr,name,(long long)*maxindp,(long)M->allocsize,HDDvaluesize,prevsize,needed);
        }
    }
    return(M->fileptr);
}

void *iguana_kvensure(struct iguana_info *coin,struct iguanakv *kv,uint32_t ind)
{
    char fname[512]; void *origptr; int32_t maxitemind,n,rwflag = 1;
    if ( (int32_t)ind < 0 )
        ind = 0;
    origptr = kv->HDDitems;
    kv->HDDitems = _iguana_kvensure(coin,rwflag,&kv->maxitemind,kv->name,kv->fname,kv->mult,kv->incr,ind,&kv->M,kv->HDDvaluesize);
    if ( kv->HDDitemsp != 0 )
        *kv->HDDitemsp = kv->HDDitems;
    n = (int32_t)(kv->M.allocsize / kv->HDDvaluesize);
    if ( ind < n )
        ind = n;
    if ( kv->valuesize3 != 0 )
    {
        sprintf(fname,"%s3",kv->fname);
        if ( (kv->HDDitems3= _iguana_kvensure(coin,rwflag,&maxitemind,kv->name,fname,kv->mult,kv->incr,ind,&kv->M3,kv->valuesize3)) == 0 )
        {
            printf("HDDitems3 null ptr for %s\n",fname);
            return(0);
        }
        //printf("third file\n");
        if ( kv->HDDitems3p != 0 )
            *kv->HDDitems3p = kv->HDDitems3;
    }
    if ( kv->valuesize2 != 0 )
    {
        sprintf(fname,"%s2",kv->fname);
        if ( (kv->HDDitems2= _iguana_kvensure(coin,rwflag,&maxitemind,kv->name,fname,kv->mult,kv->incr,ind,&kv->M2,kv->valuesize2)) == 0 )
        {
            printf("HDDitems3 null ptr for %s\n",fname);
            return(0);
        }
        //printf("second file\n");
        if ( kv->HDDitems2p != 0 )
            *kv->HDDitems2p = kv->HDDitems2;
    }
    if ( origptr != 0 && origptr != kv->M.fileptr && (kv->flags & IGUANA_ITEMIND_DATA) != 0 )
    {
        if ( iguana_kviterate(coin,kv,(int64_t)((int64_t)kv->HDDitems - (int64_t)origptr),iguana_kvfixiterator) != 0 )
            printf("ERROR relinked pointers\n");
        else printf("hashtable relinked\n");
        kv->incr *= 1.25;
    }
    return(kv->HDDitems);
}

void *iguana_kvsaveiterator(struct iguana_info *coin,struct iguanakv *kv,struct iguana_kvitem *item,uint64_t args,void *key,void *value,int32_t valuesize)
{
    FILE *fp = (FILE *)args;
    if ( args != 0 )
    {
        if ( fwrite(value,1,kv->RAMvaluesize,fp) != kv->RAMvaluesize )
        {
            printf("Error saving key.[%d]\n",kv->RAMvaluesize);
            return(value);
        }
    }
    return(0);
}

long iguana_kvsave(struct iguana_info *coin,struct iguanakv *kv)
{
    FILE *fp; long retval = -1; char fname[512],oldfname[512],cmd[512];
    sprintf(fname,"%s.tmp",kv->name);
    if ( (fp= fopen(fname,"wb")) != 0 )
    {
        if ( iguana_kviterate(coin,kv,(uint64_t)fp,iguana_kvsaveiterator) == 0 )
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
        retval = system(cmd);
        sprintf(cmd,"%s %s %s",OS_mvstr(),fname,kv->name);
        retval = system(cmd);
    }
    return(retval);
}

int32_t iguana_valuesize(struct iguana_info *coin,struct iguanakv *kv)
{
    int32_t valuesize = kv->RAMvaluesize;
    return(valuesize);
}

int32_t iguana_itemsize(struct iguana_info *coin,struct iguanakv *kv)
{
    int32_t itemsize = sizeof(struct iguana_kvitem);
    if ( (kv->flags & IGUANA_ITEMIND_DATA) == 0 )
        itemsize += iguana_valuesize(coin,kv);
    return(itemsize);
}

void *iguana_itemvalue(struct iguana_info *coin,void **itemkeyp,struct iguanakv *kv,void *ptr,struct iguana_kvitem *item)
{
    void *itemvalue = 0;
    *itemkeyp = 0;
    if ( (kv->flags & IGUANA_ITEMIND_DATA) != 0 )
    {
        if ( ptr != 0 )
        {
            *itemkeyp = &((uint8_t *)ptr)[kv->keyoffset];
            itemvalue = ptr;
        } else printf("error setting itemvalue\n");
    }
    if ( *itemkeyp == 0 )
    {
        *itemkeyp = item->keyvalue;
        itemvalue = &item->keyvalue[kv->keysize];
    }
    return(itemvalue);
}

void *iguana_itemptr(struct iguana_info *coin,struct iguanakv *kv,uint32_t itemind)
{
    void *ptr = kv->HDDitems;
    //printf("%s itemind.%d\n",kv->name,itemind);
    if ( ptr == 0 || itemind >= kv->maxitemind )
    {
        kv->HDDitems = iguana_kvensure(coin,kv,itemind+1);
        if ( (ptr= kv->HDDitems) == 0 )
        {
            printf("SECOND ERROR %s overflow? %p itemind.%llu vs max.%llu\n",kv->name,ptr,(long long)itemind,(long long)kv->maxitemind);
            return(0);
        }
    }
    ptr = (void *)((uint64_t)ptr + kv->HDDvaluesize*itemind);
    return(ptr);
}

void iguana_copy(struct iguana_info *coin,struct iguanakv *kv,int32_t rwflag,void *itemvalue,void *value,int32_t valuesize)
{
    void *src,*dest;
    /*if ( (kv->flags & IGUANA_MAPPED_ITEM) != 0 && rwflag != 0 )
     {
     itemvalue = (void *)(((uint64_t))itemvalue + sizeof(UT_hash_handle));
     value = (void *)(((uint64_t))value + sizeof(UT_hash_handle));
     valuesize -= sizeof(UT_hash_handle);
     //printf("value.%p itemvalue.%p valuesize.%d\n",value,itemvalue,valuesize);
     }*/
    if ( rwflag != 0 )
        src = value, dest = itemvalue;
    else src = itemvalue, dest = value;
    memcpy(dest,src,valuesize);
}

static int32_t iguana_RWmmap(int32_t writeflag,void *value,struct iguana_info *coin,struct iguanakv *kv,uint32_t itemind)
{
    static const uint8_t zeroes[4096];
    void *ptr,*itemvalue=0; int32_t i,itemsize,valuesize,retval = 0; 
    itemsize = iguana_itemsize(coin,kv);
    valuesize = iguana_valuesize(coin,kv);
    if ( (ptr= iguana_itemptr(coin,kv,itemind)) != 0 )
    {
        //itemvalue = iguana_itemvalue(coin,&itemkey,kv,ptr,0);
        if ( writeflag != 0 )
        {
            //struct iguana777_addrinfo *A; struct coin_offsets B,tmpB;
            //itemsize = kv->RAMvaluesize;
            /*if ( strcmp(sp->name,"addrinfos") == 0 )
             {
             A = ptr;
             itemsize = (sizeof(*A) - sizeof(A->coinaddr) + A->addrlen + A->scriptlen);
             }*/
            if ( writeflag == 1 && (kv->flags & IGUANA_VOLATILE) == 0 )
            {
                /*if ( strcmp(sp->name,"blocks") == 0 )
                 {
                 memcpy(&B,ptr,sizeof(B));
                 memcpy(&tmpB,value,sizeof(tmpB));
                 if ( memcmp(&B.blockhash.bytes,zeroes,sizeof(B.blockhash)) == 0 && memcmp(&B.merkleroot.bytes,zeroes,sizeof(B.merkleroot)) == 0 )
                 B.blockhash = tmpB.blockhash, B.merkleroot = tmpB.merkleroot, ptr = &B;
                 }*/
                if ( 0 && memcmp(value,itemvalue,valuesize) != 0 && valuesize <= sizeof(zeroes) )
                {
                    if ( memcmp(itemvalue,zeroes,valuesize) != 0 )
                    {
                        printf("\n");
                        for (i=0; i<valuesize; i++)
                            printf("%02x ",((uint8_t *)itemvalue)[i]);
                        printf("existing.%s %d <-- overwritten\n",kv->name,kv->RAMvaluesize);
                        for (i=0; i<valuesize; i++)
                            printf("%02x ",((uint8_t *)value)[i]);
                        printf("new value.%s %d itemind.%u fileptr.%p ptr.%p\n",kv->name,kv->RAMvaluesize,itemind,kv->M.fileptr,ptr);
                    }
                }
            }
            if ( kv->fp == 0 )
                iguana_copy(coin,kv,writeflag,ptr,value,valuesize);
            else // all ready for rb+ fp and readonly mapping, but need to init properly
            {
                /*fseek(sp->fp,(uint64_t)sp->itemsize * itemind,SEEK_SET);
                 fwrite(value,1,valuesize,sp->fp);
                 if ( memcmp(itemvalue,value,valuesize) != 0 )
                 printf("FATAL: write mmap error\n"), getchar();*/
                printf("iguana_RWmmap: need to test sp->fp first\n"), exit(1);
            }
        }
        else iguana_copy(coin,kv,writeflag,ptr,value,valuesize);
    } else retval = -2;
    return(retval);
}

void iguana_kvlock(struct iguana_info *coin,struct iguanakv *kv)
{
    if ( kv->threadsafe != 0 )
        portable_mutex_lock(&kv->KVmutex);
}

void iguana_kvunlock(struct iguana_info *coin,struct iguanakv *kv)
{
    if ( kv->threadsafe != 0 )
        portable_mutex_unlock(&kv->KVmutex);
}

int32_t iguana_kvdelete(struct iguana_info *coin,struct iguanakv *kv,void *key)
{
    int32_t retval = -1; struct iguana_kvitem *ptr = 0;
    if ( kv == 0 )
        return(-1);
    iguana_kvlock(coin,kv);
    HASH_FIND(hh,kv->hashtables[((uint8_t *)key)[kv->keysize>>1]],key,kv->keysize,ptr);
    if ( ptr != 0 )
    {
        HASH_DELETE(hh,kv->hashtables[((uint8_t *)key)[kv->keysize>>1]],ptr);
        if ( (kv->flags & IGUANA_MAPPED_ITEM) == 0 )
            myfree(ptr,iguana_itemsize(coin,kv));
        retval = 0;
    }
    iguana_kvlock(coin,kv);
    return(retval);
}

void *_iguana_kvread(struct iguana_info *coin,struct iguanakv *kv,void *key,void *value,uint32_t *itemindp)
{
    void *itemkey,*itemvalue,*ptr=0; int32_t valuesize,itemind = 0; struct iguana_kvitem *item = 0;
    if ( kv == 0 )
    {
        printf("iguana_kvread: null ramkv??\n");
        return(0);
    }
    if ( kv->keysize == 0 )
    {
        printf("kvwrite %s only supports itemind MMap access\n",kv->name);
        return(0);
    }
    valuesize = iguana_valuesize(coin,kv);
    //printf("search for [%llx] keysize.%d\n",*(long long *)key,kv->keysize);
    HASH_FIND(hh,kv->hashtables[((uint8_t *)key)[kv->keysize>>1]],key,kv->keysize,item);
    if ( item != 0 )
    {
        if ( itemindp != 0 )
            *itemindp = itemind = item->hh.itemind;
        if ( (kv->flags & IGUANA_ITEMIND_DATA) != 0 )
            ptr = iguana_itemptr(coin,kv,itemind);
        if ( (itemvalue= iguana_itemvalue(coin,&itemkey,kv,ptr,item)) != 0 )
        {
            //printf("itemind.%d: key.%p value.%p valuesize.%d\n",itemind,itemkey,itemvalue,valuesize);
            iguana_copy(coin,kv,0,itemvalue,value,valuesize);
        }
        else printf("_kvread null itemvalue for itemind.%d\n",itemind);
        return(value);
    }
    //printf("cache miss %s\n",bits256_str(*(bits256 *)key));
    if ( itemindp != 0 )
        *itemindp = 0;
    return(0);
}

void *_iguana_kvwrite(struct iguana_info *coin,struct iguanakv *kv,void *key,void *value,uint32_t *itemindp)
{
    void *ptr=0,*itemvalue=0,*itemkey=0; struct iguana_kvitem *item = 0; uint32_t itemsize,valuesize,itemind = *itemindp;
    if ( kv == 0 )
        return(0);
    valuesize = iguana_valuesize(coin,kv);
    itemsize = iguana_itemsize(coin,kv);
    if ( kv->keysize == 0 )
    {
        printf("kvwrite %s only supports itemind MMap access\n",kv->name);
        return(0);
    }
    HASH_FIND(hh,kv->hashtables[((uint8_t *)key)[kv->keysize>>1]],key,kv->keysize,item);
    if ( item != 0 )
    {
        if ( 0 && itemind != item->hh.itemind && itemind != (uint32_t)-1 )
        {
            printf("%s override itemind %d -> %d\n",kv->name,item->hh.itemind,itemind);
            item->hh.itemind = itemind;
        } else itemind = item->hh.itemind;
        *itemindp = itemind;
        if ( (kv->flags & IGUANA_ITEMIND_DATA) != 0 )
            ptr = iguana_itemptr(coin,kv,itemind);
        if ( (itemvalue= iguana_itemvalue(coin,&itemkey,kv,ptr,item)) != 0 )
        {
            if ( memcmp(itemvalue,value,valuesize) != 0 )
            {
                //printf("%s: item.%d updating %p\n",kv->name,item->hh.itemind,key);
                iguana_copy(coin,kv,1,itemvalue,value,valuesize);
                kv->updated++;
            }
        } else printf("kvwrite null itemvalue itemind.%d\n",itemind);
        return(item);
    }
    else
    {
        kv->numkeys++;
        if ( itemind == (uint32_t)-1 )
            itemind = kv->numkeys;
        *itemindp = itemind;
        if ( item == 0 )
        {
            if ( (kv->flags & IGUANA_ITEMIND_DATA) != 0 )
                ptr = iguana_itemptr(coin,kv,itemind);
            item = ((kv->flags & IGUANA_MAPPED_ITEM) == 0) ? mycalloc('I',1,itemsize) : iguana_tmpalloc(coin,kv->name,&kv->HASHPTRS,itemsize);
            if ( item == 0 )
                printf("fatal out of mem error\n"), getchar();
        }
        itemvalue = iguana_itemvalue(coin,&itemkey,kv,ptr,item);
    }
    if ( itemvalue != 0 && itemkey != 0 && item != 0 )
    {
        valuesize = iguana_valuesize(coin,kv);
        item->hh.itemind = itemind;
        iguana_copy(coin,kv,1,itemvalue,value,valuesize);
        memcpy(itemkey,key,kv->keysize);
        //if ( strcmp(kv->name,"txids") == 0 )
        //printf("add.(%s) itemind.%d kv->numkeys.%d keysize.%d (%s) valuesize.%d:%d\n",kv->name,itemind,kv->numkeys,kv->keysize,bits256_str(*(bits256 *)key),kv->HDDvaluesize,kv->RAMvaluesize);
        HASH_ADD_KEYPTR(hh,kv->hashtables[((uint8_t *)itemkey)[kv->keysize>>1]],itemkey,kv->keysize,item);
        kv->M.dirty++;
        HASH_FIND(hh,kv->hashtables[((uint8_t *)key)[kv->keysize>>1]],key,kv->keysize,item);
        if ( kv->dispflag != 0 || item == 0 || item->hh.itemind != itemind )
            fprintf(stderr,">> %s found item.%p iguana_kvwrite numkeys.%d kv.(%p) table.%p write kep.%p size.%d, %p value.(%08x) size.%d itemind.%d:%d\n",kv->name,item,kv->numkeys,key,kv->hashtables[((uint8_t *)itemkey)[kv->keysize>>1]],itemkey,kv->keysize,itemvalue,itemvalue!=0?calc_crc32(0,itemvalue,valuesize):0,valuesize,item!=0?item->hh.itemind:0,itemind);
        if ( item != 0 )
            return(value);
        else printf("null item after find kvwrite error\n"), getchar();
    } else printf("kvwrite pointer error %p %p %p\n",itemkey,itemvalue,item), getchar();
    return(0);
}

void *iguana_kvread(struct iguana_info *coin,struct iguanakv *kv,void *key,void *value,uint32_t *itemindp)
{
    void *retptr = 0;
   // if ( strcmp(kv->name,"txids") == 0 )
   // printf("iguana_kvread.(%s) key.%p keysize.%d flag.%d itemind.%d\n",kv->name,key,kv->keysize,kv->flags,*itemindp);
    portable_mutex_lock(&kv->MMmutex);
    if ( key == 0 || kv->keysize == 0 )
    {
        if ( iguana_RWmmap(0,value,coin,kv,*itemindp) == 0 )
            retptr = value;
        else printf("%s %d vs %d RMmmap.0 error\n",kv->name,*itemindp,(int32_t)(kv->M.allocsize/kv->HDDvaluesize));
    } else retptr = _iguana_kvread(coin,kv,key,value,itemindp);
    portable_mutex_unlock(&kv->MMmutex);
    return(retptr);
}

void *iguana_kvwrite(struct iguana_info *coin,struct iguanakv *kv,void *key,void *value,uint32_t *itemindp)
{
    void *retptr = 0;
    portable_mutex_lock(&kv->MMmutex);
    if ( key == 0 || kv->keysize == 0 )
    {
        kv->M.dirty++;
        if ( iguana_RWmmap(1,value,coin,kv,*itemindp) == 0 )
            retptr = value;
        else printf("%s %d vs %d RMmmap.1 error\n",kv->name,*itemindp,(int32_t)(kv->M.allocsize/kv->HDDvaluesize));
    } else retptr = _iguana_kvwrite(coin,kv,key,value,itemindp);
    portable_mutex_unlock(&kv->MMmutex);
    return(retptr);
}

int32_t iguana_kvchecktable(struct iguana_info *coin,struct iguanakv *kv)
{
    uint32_t itemind,checkind; int32_t err = 0; uint8_t key[8192];
    for (itemind=1; itemind<=kv->numkeys; itemind++)
    {
        if ( iguana_RWmmap(0,kv->space,coin,kv,itemind) == 0 )
        {
            if ( kv->keysize != 0 && kv->keysize < sizeof(key) )
            {
                memcpy(key,(void *)((long)kv->space + kv->keyoffset),kv->keysize);
                if ( _iguana_kvread(coin,kv,key,kv->space,&checkind) == 0 || checkind != itemind )
                {
                    printf("kvread.%s miscompares checkind.%d vs %d\n",kv->name,checkind,itemind);
                    err++;
                }
            }
        } else err++, printf("%s itemind.%d doesnt map properly\n",kv->name,itemind);
    }
    return(-err);
}

void *iguana_kviterate(struct iguana_info *coin,struct iguanakv *kv,uint64_t args,void *(*iterator)(struct iguana_info *coin,struct iguanakv *kv,struct iguana_kvitem *item,uint64_t args,void *key,void *value,int32_t valuesize))
{
    struct iguana_kvitem *item,*tmp; int32_t t; void *ptr=0,*itemvalue,*itemkey=0,*retval = 0;
    if ( kv == 0 )
        return(0);
    for (t=0; t<0x100; t++)
    {
        HASH_ITER(hh,kv->hashtables[t],item,tmp)
        {
            if ( (kv->flags & IGUANA_ITEMIND_DATA) != 0 )
                ptr = iguana_itemptr(coin,kv,item->hh.itemind);
            if ( (itemvalue= iguana_itemvalue(coin,&itemkey,kv,ptr,item)) != 0 && itemkey != 0 )
            {
                if ( (retval= (*iterator)(coin,kv,item,args,itemkey,itemvalue,kv->RAMvaluesize)) != 0 )
                    return(retval);
            } else return(retval);
        }
    }
    return(0);
}

int32_t iguana_kvtruncate(struct iguana_info *coin,struct iguanakv *kv,uint32_t maxitemind)
{
    struct iguana_kvitem *item,*tmp; int32_t t,n = 0;
    if ( kv->numkeys < maxitemind )
        return(-1);
    for (t=0; t<0x100; t++)
    {
        HASH_ITER(hh,kv->hashtables[t],item,tmp)
        {
            if ( item->hh.itemind >= maxitemind )
            {
                HASH_DEL(kv->hashtables[t],item);
                if ( (kv->flags & IGUANA_MAPPED_ITEM) == 0 )
                    myfree(item,iguana_itemsize(coin,kv));
                n++;
            }
        }
    }
    printf(">>>>>>>>>> kv.%s truncated.%d to maxitemind.%d\n",kv->name,n,maxitemind);
    kv->numkeys = maxitemind;
    return(iguana_kvchecktable(coin,kv));
}

void iguana_kvfree(struct iguana_info *coin,struct iguanakv *kv)
{
    struct iguana_kvitem *ptr,*tmp; int32_t t;
    if ( kv != 0 )
    {
        iguana_kvlock(coin,kv);
        for (t=0; t<0x100; t++)
        {
            HASH_ITER(hh,kv->hashtables[t],ptr,tmp)
            {
                HASH_DEL(kv->hashtables[t],ptr);
                if ( (kv->flags & IGUANA_MAPPED_ITEM) == 0 )
                    myfree(ptr,iguana_itemsize(coin,kv));
            }
        }
        iguana_kvunlock(coin,kv);
        myfree(kv,sizeof(*kv));
    }
}

int32_t iguana_kvclone(struct iguana_info *coin,struct iguanakv *clone,struct iguanakv *kv)
{
    void *ptr=0,*itemkey,*itemvalue; struct iguana_kvitem *item,*tmp; int32_t t,n = 0;
    printf("need to add support for mapped data\n");
    if ( kv != 0 )
    {
        for (t=0; t<0x100; t++)
        {
            HASH_ITER(hh,kv->hashtables[t],item,tmp)
            {
                if ( (kv->flags & IGUANA_ITEMIND_DATA) != 0 )
                    ptr = iguana_itemptr(coin,kv,item->hh.itemind);
                if ( (itemvalue= iguana_itemvalue(coin,&itemkey,kv,ptr,item)) != 0 && itemkey != 0 )
                {
                    iguana_kvwrite(coin,clone,itemkey,itemvalue,&item->hh.itemind);
                    n++;
                }
            }
        }
    }
    return(n);
}

int32_t iguana_kvdisp(struct iguana_info *coin,struct iguanakv *kv)
{
    struct iguana_kvitem *item,*tmp; void *ptr=0,*itemkey,*itemvalue; int32_t t,n = 0; char hexstr[8192];
    printf("iguana_kvdisp.(%s) numkeys.%d\n",kv->name,kv->numkeys);
    if ( kv == 0 )
        return(0);
    for (t=0; t<0x100; t++)
    {
        HASH_ITER(hh,kv->hashtables[t],item,tmp)
        {
            if ( (kv->flags & IGUANA_ITEMIND_DATA) != 0 )
                ptr = iguana_itemptr(coin,kv,item->hh.itemind);
            if ( (itemvalue= iguana_itemvalue(coin,&itemkey,kv,ptr,item)) != 0 )
            {
                init_hexbytes_noT(hexstr,itemvalue,kv->RAMvaluesize);
                char str[65];
                bits256_str(str,*(bits256 *)itemkey);
                printf("itemind.%d %s %s len.%d height.%d\n",item->hh.itemind,str,hexstr,kv->RAMvaluesize,((struct iguana_block *)itemvalue)->height);
            }
            n++;
        }
    }
    printf("iguana_kvdisp.(%s) n.%d items\n",kv->name,n);
    return(n);
}
#endif

