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


#define uthash_malloc(size) ((ramchain->hashmem == 0) ? mycalloc('u',1,size) : iguana_memalloc(ramchain->hashmem,size,1))
#define uthash_free(ptr,size) ((ramchain->hashmem == 0) ? myfree(ptr,size) : 0)

//#define HASH_BLOOM 16
//#define HASH_INITIAL_NUM_BUCKETS_LOG2 5

#include "iguana777.h"
#include "exchanges/bitcoin.h"
//void iguana_stub(void *ptr,int size) { }//printf("uthash_free ptr.%p %d\n",ptr,size); }

#define iguana_hashfind(ramchain,selector,key) iguana_hashsetPT(ramchain,selector,key,0)

struct iguana_kvitem *iguana_hashsetPT(struct iguana_ramchain *ramchain,int32_t selector,void *key,uint32_t itemind)
{
    struct iguana_kvitem *tmp,*ptr = 0; int32_t allocsize,keylen; char str[65];
    allocsize = (int32_t)(sizeof(*ptr));
    if ( selector == 'T' )
    {
        keylen = sizeof(bits256);
        HASH_FIND(hh,ramchain->txids,key,keylen,ptr);
    }
    else if ( selector == 'P' )
    {
        keylen = 20;
        HASH_FIND(hh,ramchain->pkhashes,key,keylen,ptr);
    }
    else return(0);
    init_hexbytes_noT(str,key,keylen);
    if ( ptr == 0 && itemind != 0 )
    {
        if ( ramchain->hashmem != 0 )
            ptr = iguana_memalloc(ramchain->hashmem,allocsize,1);
        else
        {
            ptr = mycalloc('e',1,allocsize);
            printf("alloc.%d\n",allocsize);
        }
        if ( ptr == 0 )
            printf("fatal alloc errorC in hashset\n"), exit(-1);
        if ( 0 && ramchain->expanded && selector == 'T' )
            printf("hashmem.%p selector.%c added.(%s) itemind.%x ptr.%p\n",ramchain->hashmem,selector,str,itemind,ptr);
        if ( selector == 'T' )
            HASH_ADD_KEYPTR(hh,ramchain->txids,key,keylen,ptr);
        else HASH_ADD_KEYPTR(hh,ramchain->pkhashes,key,keylen,ptr);
        ptr->hh.itemind = itemind;
        //if ( strcmp(str,"0000000000000000000000000000000000000000000000000000000000000000") == 0 )
        //    printf("added null txid?\n"), getchar();
        if ( 0 && ramchain->expanded && selector == 'T' )
            printf("selector.%c added.(%s) itemind.%x ptr.%p tmp.%p\n",selector,str,itemind,ptr,tmp);
        if ( itemind == 0 )
            printf("negative itemind\n"), exit(-1);
        if ( 0 )
        {
            if ( selector == 'T' )
                HASH_FIND(hh,ramchain->txids,key,keylen,tmp);
            else HASH_FIND(hh,ramchain->pkhashes,key,keylen,tmp);
            if ( tmp != ptr )
            {
                printf("(%s) hashmem.%p selector.%c %s search error %p != %p itemind.%x\n",str,ramchain->hashmem,selector,str,ptr,tmp,itemind), exit(-1);
            }
        }
    }
    return(ptr);
}

void iguana_blocksetcounters(struct iguana_info *coin,struct iguana_block *block,struct iguana_ramchain * ramchain)
{
    block->RO.firsttxidind = ramchain->H.txidind;
    block->RO.firstvout = ramchain->H.unspentind;
    block->RO.firstvin = ramchain->H.spendind;
    block->RO.firstpkind = ramchain->pkind;
    block->RO.firstexternalind = ramchain->externalind;
}

int32_t iguana_peerfname(struct iguana_info *coin,int32_t *hdrsip,char *dirname,char *fname,uint32_t ipbits,bits256 hash2,bits256 prevhash2,int32_t numblocks,int32_t dispflag)
{
    struct iguana_bundle *bp; int32_t bundlei,subdir; char str[65];
    *hdrsip = -1; ipbits = 0;
    fname[0] = 0;
    //if ( ipbits == 0 )
    //    printf("illegal ipbits.%d\n",ipbits), getchar();
    bp = 0, bundlei = -2;
    if ( (bp= iguana_bundlefind(coin,&bp,&bundlei,hash2)) == 0 )
    {
        bp = 0, bundlei = -2;
        if ( bits256_nonz(prevhash2) == 0 || (bp= iguana_bundlefind(coin,&bp,&bundlei,prevhash2)) == 0 || bundlei >= coin->chain->bundlesize-1 )
        {
            if ( 0 && dispflag != 0 )
                printf("iguana_peerfname error finding.(%s) spec.%p bp.%p\n",bits256_str(str,hash2),bp!=0?bp->speculative:0,bp);
            return(-2);
        }
        else bundlei++;
    }
    hash2 = bp->hashes[0], *hdrsip = bp->hdrsi;
    subdir = bp->bundleheight / IGUANA_SUBDIRDIVISOR;
    if ( numblocks == 1 )
    {
        sprintf(fname,"%s/%s/%d",dirname,coin->symbol,subdir), OS_ensure_directory(fname);
        sprintf(fname,"%s/%s/%d/%d",dirname,coin->symbol,subdir,bp->bundleheight), OS_ensure_directory(fname);
        if ( bits256_nonz(bp->hashes[bundlei]) != 0 )
            sprintf(fname,"%s/%s/%d/%d/%s_%u.%d",dirname,coin->symbol,subdir,bp->bundleheight,bits256_str(str,bp->hashes[bundlei]),ipbits>1?ipbits:*hdrsip,bundlei);
        else
        {
            printf("no hash for [%d:%d]\n",bp->hdrsi,bundlei);
            return(-3);
        }
    }
    else //if ( strncmp(GLOBAL_DBDIR,dirname,strlen(GLOBAL_DBDIR)) == 0 )
    {
        sprintf(fname,"%s/%s/%d",dirname,coin->symbol,subdir), OS_ensure_directory(fname);
        sprintf(fname,"%s/%s/%d/%s_%d.%u",dirname,coin->symbol,subdir,bits256_str(str,hash2),numblocks,ipbits>1?ipbits:*hdrsip);
//#ifndef __PNACL__
//        sprintf(fname,"%s/%s/%s_%d.%u",dirname,coin->symbol,bits256_str(str,hash2),numblocks,ipbits>1?ipbits:*hdrsip);
//#endif
    } //else sprintf(fname,"%s/%s.%u",dirname,bits256_str(str,hash2),bp->bundleheight);
    OS_compatible_path(fname);
    return(bundlei);
}

int32_t iguana_peerfile_exists(struct iguana_info *coin,struct iguana_peer *addr,char *dirname,char *fname,bits256 hash2,bits256 prevhash2,int32_t numblocks)
{
    FILE *fp; int32_t bundlei,hdrsi;
    if ( (bundlei= iguana_peerfname(coin,&hdrsi,dirname,fname,addr!=0?(uint32_t)addr->ipbits:0,hash2,prevhash2,numblocks,1)) >= 0 )
    {
        OS_compatible_path(fname);
        if ( (fp= fopen(fname,"rb")) == 0 )
            bundlei = -1;
        else fclose(fp);
    }
    return(bundlei);
}

#define RAMCHAIN_FUNC struct iguana_ramchain *ramchain,struct iguana_blockRO *B,struct iguana_txid *T,struct iguana_unspent20 *U,struct iguana_spend256 *S,struct iguana_pkhash *P,struct iguana_account *A,bits256 *X,struct iguana_unspent *Ux,struct iguana_spend *Sx,uint8_t *TXbits,uint8_t *PKbits,uint8_t *Kspace
#define RAMCHAIN_PTRPS struct iguana_ramchain *ramchain,struct iguana_blockRO **B,struct iguana_txid **T,struct iguana_unspent20 **U,struct iguana_spend256 **S,struct iguana_pkhash **P,struct iguana_account **A,bits256 **X,struct iguana_unspent **Ux,struct iguana_spend **Sx,uint8_t **TXbits,uint8_t **PKbits,uint8_t **Kspace

#define _RAMCHAIN_ARG B,T,U,S,P,A,X,Ux,Sx,TXbits,PKbits,Kspace
#define RAMCHAIN_ARG ramchain,_RAMCHAIN_ARG
#define MAPCHAIN_ARG mapchain,_RAMCHAIN_ARG
#define MAPCHAIN_PTRS mapchain,&B,&T,&U,&S,&P,&A,&X,&Ux,&Sx,&TXbits,&PKbits,&Kspace

#define RAMCHAIN_PTRS ramchain,&B,&T,&U,&S,&P,&A,&X,&Ux,&Sx,&TXbits,&PKbits,&Kspace
#define RAMCHAIN_DECLARE struct iguana_blockRO *B; struct iguana_txid *T; struct iguana_unspent20 *U; struct iguana_spend256 *S; struct iguana_pkhash *P; struct iguana_account *A; bits256 *X; struct iguana_unspent *Ux; struct iguana_spend *Sx; uint8_t *TXbits,*PKbits,*Kspace;
#define RAMCHAIN_ZEROES B = 0, Ux = 0, Sx = 0, P = 0, A = 0, X = 0, Kspace = TXbits = PKbits = 0, U = 0, S = 0, T = 0

#define RAMCHAIN_DESTARG dest,destB,destT,destU,destS,destP,destA,destX,destUx,destSx,destTXbits,destPKbits,destKspace
#define RAMCHAIN_DESTPTRS dest,&destB,&destT,&destU,&destS,&destP,&destA,&destX,&destUx,&destSx,&destTXbits,&destPKbits,&destKspace
#define RAMCHAIN_DESTDECLARE struct iguana_blockRO *destB; struct iguana_txid *destT; struct iguana_unspent20 *destU; struct iguana_spend256 *destS; struct iguana_pkhash *destP; struct iguana_account *destA; bits256 *destX; struct iguana_unspent *destUx; struct iguana_spend *destSx; uint8_t *destTXbits,*destPKbits,*destKspace;

uint32_t iguana_ramchain_addtxid(struct iguana_info *coin,RAMCHAIN_FUNC,bits256 txid,int32_t numvouts,int32_t numvins,uint32_t locktime,uint32_t version,uint32_t timestamp,int16_t bundlei)
{
    uint32_t txidind; struct iguana_txid *t; struct iguana_kvitem *ptr;
    if ( sizeof(*t) != 64 )
        printf("sizeof iguana_txid.%d != 64?\n",(int32_t)sizeof(*t));
    txidind = ramchain->H.txidind;
    t = &T[txidind];
    if ( ramchain->H.ROflag != 0 )
    {
        if ( t->txidind != txidind || memcmp(t->txid.bytes,txid.bytes,sizeof(bits256)) != 0 || t->numvouts != numvouts || t->numvins != numvins || t->firstvout != ramchain->H.unspentind || t->firstvin != ramchain->H.spendind || t->locktime != locktime || t->version != version || t->timestamp != timestamp )
        {
            printf("iguana_ramchain_addtxid.RO: addtxid mismatch (%d %d %d %d %d) vs. (%d %d %d %d %d)\n",t->txidind,t->numvouts,t->numvins,t->firstvout,t->firstvin,txidind,numvouts,numvins,ramchain->H.unspentind,ramchain->H.spendind);
            //getchar();
            return(0);
        }
    }
    else
    {
        if ( 0 && ramchain->expanded != 0 )
            printf("T.%p txidind.%d numvouts.%d numvins.%d\n",T,txidind,numvouts,numvins);
        t->txidind = txidind, t->txid = txid, t->numvouts = numvouts, t->numvins = numvins;
        t->bundlei = bundlei;
        t->firstvout = ramchain->H.unspentind, t->firstvin = ramchain->H.spendind;
        t->locktime = locktime, t->version = version, t->timestamp = timestamp;
        if ( t->txidind != txidind || t->firstvout != ramchain->H.unspentind || t->firstvin != ramchain->H.spendind || t->bundlei != bundlei )
        {
            printf("addtxid error: t->txidind %u != %u txidind || t->firstvout %u != %u ramchain->H.unspentind || t->firstvin %u != %u ramchain->H.spendind || t->bundlei %u != %u bundlei\n",t->txidind,txidind,t->firstvout,ramchain->H.unspentind,t->firstvin,ramchain->H.spendind,t->bundlei,bundlei);
            return(0);
        }
        if ( ramchain->expanded != 0 )
            iguana_sparseaddtx(TXbits,ramchain->H.data->txsparsebits,ramchain->H.data->numtxsparse,txid,T,txidind,ramchain);
        //if ( txidind <= 2 )
        //    printf("%p TXID.[%d] firstvout.%d/%d firstvin.%d/%d\n",t,txidind,ramchain->unspentind,numvouts,ramchain->spendind,numvins);
    }
    if ( ramchain->expanded != 0 )
    {
        if ( (ptr= iguana_hashsetPT(ramchain,'T',t->txid.bytes,txidind)) == 0 )
        {
            printf("iguana_ramchain_addtxid error adding txidind\n");
            return(0);
        }
        if ( ptr->hh.itemind != txidind )
        {
            printf("iguana_ramchain_addtxid warning: adding txidind.%u vs %u\n",txidind,ptr->hh.itemind);
        }
    }
    return(txidind);
}

uint32_t iguana_ramchain_addpkhash(struct iguana_info *coin,RAMCHAIN_FUNC,uint8_t *rmd160,int32_t pubkeyind,uint32_t unspentind,uint32_t pkind)
{
    struct iguana_kvitem *ptr; uint32_t i;
    if ( ramchain->expanded != 0 && (ptr= iguana_hashfind(ramchain,'P',rmd160)) == 0 )
    {
        if ( ramchain->H.ROflag != 0 )
        {
            if ( P[pkind].pkind != pkind ) //unspentind != 0 && (P[pkind].firstunspentind != unspentind ||
            {
                printf("iguana_ramchain_addpkhash error mismatched pkind.(%x %x) unspentind.%d\n",pkind,P[pkind].pkind,unspentind);
                exit(-1);
                return(0);
            }
            if ( memcmp(P[pkind].rmd160,rmd160,sizeof(P[pkind].rmd160)) != 0 )
            {
                for (i=0; i<20; i++)
                    printf("%02x",P[pkind].rmd160[i]);
                printf(" -> rmd160 pkind.%d\n",pkind);
                for (i=0; i<20; i++)
                    printf("%02x",rmd160[i]);
                printf(" vs rmd160\n");
                printf("iguana_ramchain_addpkhash pkind.%d  error mismatched rmd160\n",pkind);
                //getchar();
                return(pkind);
            }
            //ramchain->pkind = (pkind + 1);
        }
        else
        {
            pkind = ramchain->pkind++;
            P[pkind].pkind = pkind;
            /*if ( P[pkind].firstunspentind == 0 && unspentind != 0 )
            {
                P[pkind].firstunspentind = unspentind;
                printf("%p P[%d] <- firstunspent.%d\n",&P[pkind],pkind,unspentind);
            }*/
            memcpy(P[pkind].rmd160,rmd160,sizeof(P[pkind].rmd160));
            //for (i=0; i<20; i++)
            //    printf("%02x",rmd160[i]);
            //printf(" -> rmd160 pkind.%d \n",pkind);
            if ( ramchain->expanded != 0 )
                iguana_sparseaddpk(PKbits,ramchain->H.data->pksparsebits,ramchain->H.data->numpksparse,rmd160,P,pkind,ramchain);
        }
        if ( (ptr= iguana_hashsetPT(ramchain,'P',&P[pkind],pkind)) == 0 )
        {
            printf("iguana_ramchain_addpkhash error adding pkhash pkind.%d\n",pkind);
            return(0);
        }
    }
    return(pkind);
}

uint32_t iguana_ramchain_addunspent20(struct iguana_info *coin,struct iguana_peer *addr,RAMCHAIN_FUNC,uint64_t value,uint8_t *script,int32_t scriptlen,bits256 txid,int32_t vout,int8_t type,struct iguana_bundle *bp,uint8_t rmd160[20])
{
    uint32_t unspentind; struct iguana_unspent20 *u; long scriptpos; struct vin_info V; char asmstr[IGUANA_MAXSCRIPTSIZE*2+1];
    unspentind = ramchain->H.unspentind++;
    u = &U[unspentind];
    if ( scriptlen > 0 )
    {
        memset(&V,0,sizeof(V));
        if ( type < 0 )
        {
            type = iguana_calcrmd160(coin,asmstr,&V,script,scriptlen,txid,vout,0xffffffff);
            if ( (type == 12 && scriptlen == 0) || (type == 1 && bitcoin_pubkeylen(script+1) <= 0) )
            {
                int32_t i; for (i=0; i<scriptlen; i++)
                    printf("%02x",script[i]);
                printf(" script type.%d\n",type);
            }
            //int32_t i; for (i=0; i<scriptlen; i++)
            //    printf("%02x",script[i]);
            //char str[65]; printf("  type.%d %s\n",type,bits256_str(str,txid));
            memcpy(rmd160,V.rmd160,sizeof(V.rmd160));
        } //else printf("iguana_ramchain_addunspent20: unexpected non-neg type.%d\n",type);
    }
    if ( ramchain->H.ROflag != 0 )
    {
        if ( u->txidind != ramchain->H.txidind || u->value != value || memcmp(u->rmd160,rmd160,sizeof(u->rmd160)) != 0 )
        {
            printf("iguana_ramchain_addunspent20: mismatched values.(%.8f %d) vs (%.8f %d)\n",dstr(u->value),u->txidind,dstr(value),ramchain->H.txidind);
            return(0);
        }
    }
    else
    {
        u->value = value;
        u->type = type;
        memcpy(u->rmd160,rmd160,sizeof(u->rmd160));
        if ( type == IGUANA_SCRIPT_76AC )
        {
            static uint64_t totalsize;
            totalsize += scriptlen;
            char str[65];
            if ( (rand() % 100000) == 0 )
                fprintf(stderr,"IGUANA_SCRIPT_76AC type.%d scriptlen.%d bp.%p %s\n",type,scriptlen,bp,mbstr(str,totalsize));
        }
        u->scriptlen = scriptlen;
        u->scriptpos = 0;
        u->fileid = 0;
        if ( scriptlen > 0 && script != 0 )
        {
            memset(&V,0,sizeof(V));
            V.spendlen = iguana_scriptgen(coin,&V.M,&V.N,V.coinaddr,V.spendscript,asmstr,u->rmd160,type,(const struct vin_info *)&V,vout);
            if ( V.spendlen != scriptlen || memcmp(V.spendscript,script,scriptlen) != 0 )
            {
                if ( addr != 0 && addr->voutsfp != 0 )
                {
#ifdef __PNACL__
                    //static portable_mutex_t mutex;
                    //portable_mutex_lock(&mutex);
#endif
                    u->fileid = (uint32_t)addr->addrind;
                    scriptpos = ftell(addr->voutsfp);
                    if ( (u->scriptpos= (uint32_t)scriptpos) == 0 )
                        fputc(0,addr->voutsfp), u->scriptpos++, scriptpos++;
                    if ( u->scriptpos != scriptpos || fwrite(script,1,scriptlen,addr->voutsfp) != scriptlen )
                        printf("error writing vout scriptlen.%d errno.%d or scriptpos.%lld != %u\n",scriptlen,errno,(long long)scriptpos,u->scriptpos);
                    else addr->dirty[0]++;
#ifdef __PNACL__
                    //portable_mutex_unlock(&mutex);
#endif
                } else printf("addr.%p unspent error fp.%p\n",addr,addr!=0?addr->voutsfp:0);
            }
        }
        u->txidind = ramchain->H.txidind;
        if ( 0 && vout > 0 )
        {
            int32_t i; for (i=0; i<20; i++)
                printf("%02x",rmd160[i]);
            printf(" rmd160 ");
            for (i=0; i<20; i++)
                printf("%02x",u->rmd160[i]);
            char str[65]; printf(" u->rmd160 type.%d scriptlen.%d:%d (%s).v%d ht.%d\n",u->type,scriptlen,u->scriptlen,bits256_str(str,txid),vout,bp->bundleheight);
        }
    }
    return(unspentind);
}

uint32_t iguana_ramchain_addunspent(struct iguana_info *coin,RAMCHAIN_FUNC,uint64_t value,uint16_t hdrsi,uint8_t *rmd160,uint16_t vout,uint8_t type,uint16_t fileid,uint32_t fpos,int32_t scriptlen,int32_t txi)
{
    uint32_t unspentind; struct iguana_unspent *u; struct iguana_kvitem *ptr; int32_t i,pkind;
    for (i=0; i<20; i++)
        if ( rmd160[i] != 0 )
            break;
    /*if ( i == 20 && vout > 0 )
    {
        printf("iguana_ramchain_addunspent: null rmd160 warning txi.%d vout.%d\n",txi,vout);
        //return(0);
    }*/
    unspentind = ramchain->H.unspentind++;
    u = &Ux[unspentind];
    if ( (ptr= iguana_hashfind(ramchain,'P',rmd160)) == 0 )
        pkind = iguana_ramchain_addpkhash(coin,RAMCHAIN_ARG,rmd160,0,unspentind,u->pkind);
    else pkind = ptr->hh.itemind;
    if ( pkind == 0 )
    {
        printf("addunspent error getting pkind\n");
        return(0);
    }
    if ( 0 )
    {
        printf(" ROflag.%d pkind.%d unspentind.%d vout.%d %.8f script[%d] uoffset.%d %d:%d type.%d A.%p\n",ramchain->H.ROflag,pkind,unspentind,vout,dstr(value),scriptlen,u->scriptpos,ramchain->H.scriptoffset,ramchain->H.data->scriptspace,type,A);
    }
    if ( ramchain->H.ROflag != 0 )
    {
        /*if ( Kspace != 0 && ((u->scriptoffset != 0 && scriptlen > 0) || type == IGUANA_SCRIPT_76AC) )
        {
            checkscript = iguana_ramchain_scriptdecode(&metalen,&checklen,Kspace,u->type,_script,u->scriptoffset,P[pkind].pubkeyoffset < ramchain->H.scriptoffset ? P[pkind].pubkeyoffset : 0);
            if ( checklen != scriptlen || (script != 0 && checkscript != 0 && memcmp(checkscript,script,scriptlen) != 0) )
            {
                printf("script mismatch len.%d vs %d or cmp error.%d\n",scriptlen,checklen,(checkscript != 0 && script != 0) ? memcmp(checkscript,script,scriptlen):0);
            } //else printf("RO spendscript match.%d\n",scriptlen);
        }*/
        if ( u->fileid != fileid || u->scriptpos != fpos || u->scriptlen != scriptlen || u->value != value || u->pkind != pkind || u->value != value || u->txidind != ramchain->H.txidind || (pkind != 0 && u->prevunspentind != A[pkind].lastunspentind) || u->vout != vout || u->hdrsi != hdrsi )
        {
            printf("iguana_ramchain_addunspent: (%d %d %d) vs (%d %d %d) mismatched values.(%d %.8f %d %d %d %d) vs (%d %.8f %d %d %d %d)\n",u->fileid,u->scriptpos,u->scriptlen,fileid,fpos,scriptlen,u->pkind,dstr(u->value),u->txidind,u->prevunspentind,u->vout,u->hdrsi,pkind,dstr(value),ramchain->H.txidind,A[pkind].lastunspentind,vout,hdrsi);
            exit(-1);
            return(0);
        }
    }
    else
    {
        u->value = value;
        //if ( type == IGUANA_SCRIPT_76AC )
        //    pubkeyoffset = P[pkind].pubkeyoffset;
        //else pubkeyoffset = 0;
        u->vout = vout, u->hdrsi = hdrsi;
        u->txidind = ramchain->H.txidind, u->pkind = pkind;
        u->prevunspentind = A[pkind].lastunspentind;
        u->fileid = fileid;
        u->scriptlen = scriptlen;
        u->scriptpos = fpos;
        u->type = type;
    }
    //printf("%p A[%d] last <- U%d\n",&A[pkind],pkind,unspentind);
    A[pkind].total += value;
    A[pkind].lastunspentind = unspentind;
    return(unspentind);
}

int32_t iguana_ramchain_txid(struct iguana_info *coin,RAMCHAIN_FUNC,bits256 *txidp,struct iguana_spend *s)
{
    uint32_t ind,external;
    memset(txidp,0,sizeof(*txidp));
    //printf("s.%p ramchaintxid vout.%x spendtxidind.%d numexternals.%d isext.%d numspendinds.%d\n",s,s->vout,s->spendtxidind,ramchain->numexternaltxids,s->external,ramchain->numspends);
    if ( s->prevout < 0 )
        return(-1);
    ind = s->spendtxidind;
    external = (ind >> 31) & 1;
    ind &= ~(1 << 31);
    if ( s->external != 0 && s->external == external && ind < ramchain->H.data->numexternaltxids )
    {
        //printf("ind.%d externalind.%d X[%d]\n",ind,ramchain->externalind,ramchain->H.data->numexternaltxids);
        *txidp = X[ind];
        return(s->prevout);
    }
    else if ( s->external == 0 && s->external == external && ind < ramchain->H.txidind )
    {
        *txidp = T[ind].txid;
        return(s->prevout);
    }
    return(-2);
}

uint32_t iguana_ramchain_addspend(struct iguana_info *coin,RAMCHAIN_FUNC,bits256 prev_hash,int32_t prev_vout,uint32_t sequence,int32_t hdrsi,uint16_t fileid,uint64_t scriptpos,int32_t vinscriptlen)
{
    struct iguana_spend *s; struct iguana_kvitem *ptr = 0; bits256 txid;
    uint32_t spendind,unspentind,txidind=0,pkind,external=0; uint64_t value = 0;
    // uint8_t _script[IGUANA_MAXSCRIPTSIZE]; int32_t metalen,i,checklen;
    spendind = ramchain->H.spendind++;
    s = &Sx[spendind];
    pkind = unspentind = 0;
    ptr = iguana_hashfind(ramchain,'T',prev_hash.bytes);
    if ( prev_vout >= 0 && ptr == 0 )
    {
        external = 1;
        txidind = ramchain->externalind++;
        if ( 0 && ramchain->expanded != 0 )
            { char str[65]; printf("%p X[%d] <- %s\n",X,txidind,bits256_str(str,prev_hash)); }
        if ( ramchain->H.ROflag != 0 )
        {
            if ( memcmp(X[txidind].bytes,prev_hash.bytes,sizeof(prev_hash)) != 0 )
            {
                char str[65],str2[65]; printf("iguana_ramchain_addspend X[%d] of %d cmperror %s vs %s\n",txidind,ramchain->H.data->numexternaltxids,bits256_str(str,X[txidind]),bits256_str(str2,prev_hash));
                return(0);
            }
        } else X[txidind] = prev_hash;
        if ( (ptr= iguana_hashsetPT(ramchain,'T',&X[txidind].bytes,txidind | (1 << 31))) == 0 )
        {
            printf("iguana_ramchain_addspend error adding external\n");
            return(0);
        }
        txidind |= (1 << 31);
    }
    else if ( ptr != 0 )
        txidind = ptr->hh.itemind;
    else if ( prev_vout >= 0 )
        printf("unexpected addspend case: null ptr prev.%d [%d] s%u\n",prev_vout,hdrsi,spendind);
    if ( prev_vout >= 0 && (external= ((txidind >> 31) & 1)) == 0 )
    {
        if ( txidind > 0 && txidind < ramchain->H.data->numtxids )
        {
            if ( (unspentind= T[txidind].firstvout + prev_vout) > 0 && unspentind < ramchain->H.data->numunspents )
            {
                value = Ux[unspentind].value;
                if ( (pkind= Ux[unspentind].pkind) == 0 || pkind >= ramchain->H.data->numpkinds )
                {
                    printf("spendind.%d -> unspendind.%d %.8f -> pkind.0x%x\n",spendind,unspentind,dstr(value),pkind);
                    return(0);
                }
            } else printf("addspend illegal unspentind.%d vs %d\n",unspentind,ramchain->H.data->numunspents);
        } else printf("addspend illegal txidind.%d vs %d\n",txidind,ramchain->H.data->numtxids), exit(-1);
    }
    if ( ramchain->H.ROflag != 0 )
    {
        iguana_ramchain_txid(coin,RAMCHAIN_ARG,&txid,s);
        if ( s->sequenceid != sequence || memcmp(txid.bytes,prev_hash.bytes,sizeof(bits256)) != 0 || s->prevout != prev_vout )
        {
            char str[65],str2[65]; printf("ramchain_addspend RO value mismatch diffseq.%x v %x (%d) vs (%d) %s vs %s\n",s->sequenceid,sequence,s->prevout,prev_vout,bits256_str(str,txid),bits256_str(str2,prev_hash));
            return(0);
        }
        /*if ( (checklen= iguana_vinscriptdecode(coin,ramchain,&metalen,_script,&Kspace[ramchain->H.data->scriptspace],Kspace,s)) != vinscriptlen || (vinscript != 0 && memcmp(_script,vinscript,vinscriptlen) != 0) )
        {
            static uint64_t counter;
            if ( counter++ < 100 )
            {
                for (i=0; i<checklen; i++)
                    printf("%02x",_script[i]);
                printf(" decoded\n");
                for (i=0; i<vinscriptlen; i++)
                    printf("%02x",vinscript[i]);
                printf(" vinscript\n");
                printf("A addspend: vinscript expand error (%d vs %d) %d\n",checklen,vinscriptlen,vinscript!=0?memcmp(_script,vinscript,vinscriptlen):0);
            }
        }*/
        //ramchain->H.scriptoffset += metalen;
    }
    else
    {
        //for (i=0; i<vinscriptlen; i++)
        //    printf("%02x",vinscript[i]);
        //printf(" SAVE vinscript len.%d\n",vinscriptlen);
        //if ( bits256_cmp(prev_hash,bits256_conv("d9151f0471a3982778c8acc623becc24bc35483bdecb07611d036209da541cde")) == 0 )
          //  printf("found spend d9151... txidind.%u (first.%u + vout.%d) u%u [%d] s%u\n",txidind,T[txidind].firstvout,prev_vout,unspentind,hdrsi,spendind);
        s->sequenceid = sequence;
        s->external = external, s->spendtxidind = txidind,
        s->prevout = prev_vout;
        s->fileid = fileid;
        s->scriptpos = scriptpos;
        s->scriptlen = vinscriptlen;
        /*static uint64_t good,bad;
        if ( 0 && iguana_metascript(coin,RAMCHAIN_ARG,s,vinscript,vinscriptlen,0) < 0 )
        {
            static long errlen,err2len; char errbuf[1024];
            errlen += vinscriptlen;
            if ( iguana_metascript(coin,RAMCHAIN_ARG,s,vinscript,vinscriptlen,1) < 0 )
            {
                err2len += vinscriptlen;
                errbuf[0] = 0;
                for (i=0; i<vinscriptlen; i++)
                    sprintf(errbuf+strlen(errbuf),"%02x",vinscript[i]);
                printf("%s <- second error with ",errbuf);
                printf(" vinscript.%d errlens %ld %ld\n",vinscriptlen,errlen,err2len);
            }
            else if ( 0 && vinscriptlen > 138 )
            {
                errbuf[0] = 0;
                for (i=0; i<vinscriptlen; i++)
                    sprintf(errbuf+strlen(errbuf),"%02x",vinscript[i]);
                printf("%s bigscript ",errbuf);
            }
            bad += vinscriptlen;
        } else good += vinscriptlen;
        if ( 0 && (rand() % 100000) == 0 )
            printf("good.%llu bad.%llu vinstats\n",(long long)good,(long long)bad);*/
        //s->hdrsi = hdrsi;
        //s->bundlei = bundlei;
        //char str[65]; printf("%s set prevout.%d -> %d\n",bits256_str(str,prev_hash),prev_vout,s->prevout);
        //if ( pkind != 0 )
        //    s->prevspendind = A[pkind].lastspendind;
    }
    if ( pkind != 0 )
    {
        //A[pkind].balance -= value;
        //A[pkind].lastspendind = spendind;
        //if ( P2[pkind].firstspendind == 0 )
        //    P2[pkind].firstspendind = spendind;
    }
    return(spendind);
}

uint32_t iguana_ramchain_addspend256(struct iguana_info *coin,struct iguana_peer *addr,RAMCHAIN_FUNC,bits256 prev_hash,int32_t prev_vout,uint8_t *vinscript,int32_t vinscriptlen,uint32_t sequence,struct iguana_bundle *bp)
{
    struct iguana_spend256 *s; uint32_t spendind; int32_t err;
    spendind = ramchain->H.spendind++;
    s = &S[spendind];
    if ( ramchain->H.ROflag != 0 )
    {
        if ( vinscriptlen != s->vinscriptlen || s->sequenceid != sequence || memcmp(s->prevhash2.bytes,prev_hash.bytes,sizeof(bits256)) != 0 || s->prevout != prev_vout ) //|| s->hdrsi != hdrsi
        {
            char str[65],str2[65]; printf("check offset %llu (%d %d) addspend.%d v %d RO value mismatch sequenceid.%x seq.%x prev_vout(%d vs %d) %s vs %s\n",(long long)s->scriptpos,vinscriptlen,s->vinscriptlen,spendind,s->spendind,s->sequenceid,sequence,s->prevout,prev_vout,bits256_str(str,s->prevhash2),bits256_str(str2,prev_hash));
            //printf("check addspend.%d vs %d RO value mismatch (%d %d:%d) vs (%d %d:%d)\n",spendind,s->spendind,s->prevout,s->hdrsi,s->bundlei,prev_vout,hdrsi,bundlei);
            //exit(-1);
            return(0);
        }
        //printf(" READ.%p spendind.%d vs %d prevout.%d hdrsi.%d:%d\n",s,spendind,s->spendind,s->prevout,s->hdrsi,s->bundlei);
    }
    else
    {
        s->sequenceid = sequence;
        s->prevhash2 = prev_hash, s->prevout = prev_vout;
        s->spendind = spendind;
        if ( (s->vinscriptlen= vinscriptlen) > 0 && vinscript != 0 && addr != 0 && addr->vinsfp != 0 && vinscriptlen < IGUANA_MAXSCRIPTSIZE)
        {
#ifdef __PNACL__
            //static portable_mutex_t mutex;
            //portable_mutex_lock(&mutex);
#endif
            s->fileid = (uint32_t)addr->addrind;
            if ( (s->scriptpos= ftell(addr->vinsfp)) == 0 )
                fputc(0,addr->vinsfp), s->scriptpos++;
            if ( (err= (int32_t)fwrite(vinscript,1,vinscriptlen,addr->vinsfp)) != vinscriptlen )
                printf("error.%d writing vinscriptlen.%d errno.%d addrind.%d\n",err,vinscriptlen,errno,addr->addrind);
            else addr->dirty[1]++;
#ifdef __PNACL__
            //portable_mutex_unlock(&mutex);
#endif
        } else s->scriptpos = 0;
        //else printf("spend256 scriptfpos.%d\n",s->scriptfpos);
        //char str[65]; printf("W.%p s.%d vout.%d/%d [%d] %s fpos.%u slen.%d\n",s,spendind,s->prevout,prev_vout,bp->hdrsi,bits256_str(str,prev_hash),s->scriptfpos,s->vinscriptlen);
    }
    return(spendind);
}

int64_t iguana_hashmemsize(int64_t numtxids,int64_t numunspents,int64_t numspends,int64_t numpkinds,int64_t numexternaltxids,int64_t scriptspace)
{
    int64_t allocsize = 0;
    allocsize += 1.25 * (scriptspace + IGUANA_MAXSCRIPTSIZE + ((numtxids + numpkinds) * (sizeof(UT_hash_handle)*2)) + (((sizeof(struct iguana_account)) * 2 * numpkinds)) + (2 * numunspents * sizeof(struct iguana_spendvector)));
    if ( allocsize >= (1LL << 32) )
    {
        printf("REALLY big hashmemsize %llu, truncate and hope for best\n",(long long)allocsize);
        allocsize = (1LL << 32) - 1;
    }
    //printf("iguana_hashmemsize T.%d U.%d S.%d P.%d X.%d -> %ld\n",numtxids,numunspents,numspends,numpkinds,numexternaltxids,(long)allocsize);
    return(allocsize);
}

void *_iguana_ramchain_setptrs(RAMCHAIN_PTRPS,struct iguana_ramchaindata *rdata)
{
    if ( rdata == 0 )
    {
        printf("_iguana_ramchain_setptrs: null rdata\n");
        return(0);
    }
    //printf("rdata.%p\n",rdata);
    *B = RAMCHAIN_PTR(rdata,Boffset);
    *T = RAMCHAIN_PTR(rdata,Toffset);
    //*B = (void *)(long)((long)rdata + (long)rdata->Boffset);
    //*T = (void *)(long)((long)rdata + (long)rdata->Toffset);
    *Kspace = RAMCHAIN_PTR(rdata,Koffset);
    //*Kspace = (void *)(long)((long)rdata + (long)rdata->Koffset);
    if ( ramchain->expanded != 0 )
    {
        *Ux = RAMCHAIN_PTR(rdata,Uoffset);
        *Sx = RAMCHAIN_PTR(rdata,Soffset);
        *P = RAMCHAIN_PTR(rdata,Poffset);
        *X = RAMCHAIN_PTR(rdata,Xoffset);
        //*Ux = (void *)(long)((long)rdata + (long)rdata->Uoffset);
        //*Sx = (void *)(long)((long)rdata + (long)rdata->Soffset);
        //*P = (void *)(long)((long)rdata + (long)rdata->Poffset);
        //*X = (void *)(long)((long)rdata + (long)rdata->Xoffset);
        //ramchain->roU2 = (void *)(long)((long)rdata + (long)rdata->U2offset);
        //ramchain->roP2 = (void *)(long)((long)rdata + (long)rdata->P2offset);
        ramchain->creditsA = RAMCHAIN_PTR(rdata,Aoffset);
        //ramchain->creditsA = (void *)(long)(long)((long)rdata + (long)rdata->Aoffset);
        //if ( (*U2= ramchain->U2) == 0 )
        //    *U2 = ramchain->U2 = ramchain->roU2;
        //if ( (*P2= ramchain->P2) == 0 )
        //    *P2 = ramchain->P2 = ramchain->roP2;
        if ( (*A= ramchain->A) == 0 )
            *A = ramchain->A = ramchain->creditsA;
        //printf("T.%p Ux.%p Sx.%p P.%p\n",*T,*Ux,*Sx,*P);
        *TXbits = RAMCHAIN_PTR(rdata,TXoffset);
        *PKbits = RAMCHAIN_PTR(rdata,PKoffset);
        //*TXbits = (void *)(long)((long)rdata + (long)rdata->TXoffset);
        //*PKbits = (void *)(long)((long)rdata + (long)rdata->PKoffset);
        *U = 0, *S = 0;
    }
    else
    {
        *U = RAMCHAIN_PTR(rdata,Uoffset);
        *S = RAMCHAIN_PTR(rdata,Soffset);
        //*U = (void *)(long)((long)rdata + (long)rdata->Uoffset);
        //*S = (void *)(long)((long)rdata + (long)rdata->Soffset);
        *Ux = 0, *Sx = 0, *P = 0, *X = 0, *A = 0, *TXbits = 0, *PKbits = 0; //*U2 = 0, *P2 = 0,
    }
    return(rdata);
}

void *iguana_ramchain_offset(char *fname,void *dest,uint8_t *lhash,FILE *fp,uint64_t fpos,void *srcptr,uint64_t *offsetp,uint64_t len,uint64_t srcsize)
{
    long err,startfpos; void *destptr = (void *)(long)((long)dest + *offsetp);
    if ( (lhash != 0 || fp != 0) && (*offsetp + len) > srcsize )
    {
        printf("ramchain_offset overflow (%p %p) offset.%ld + len.%ld %ld > %ld srcsize\n",fp,lhash,(long)*offsetp,(long)len,(long)(*offsetp + len),(long)srcsize);
        return(destptr);
    }
    if ( lhash != 0 )
    {
        //fprintf(stderr,"lhash.%p memptr.%p offset.%ld len.%ld avail.%ld srcsize.%ld\n",lhash,srcptr,(long)*offsetp,(long)len,(long)(srcsize - (*offsetp + len)),(long)srcsize);
        vcalc_sha256(0,lhash,srcptr,(uint32_t)len);
    }
    else if ( fp != 0 && len > 0 )
    {
#ifdef __PNACL__
        //static portable_mutex_t mutex;
        //portable_mutex_lock(&mutex);
#endif
        startfpos = ftell(fp);
        err = fwrite(srcptr,1,len,fp);
#ifdef __PNACL__
        //portable_mutex_unlock(&mutex);
#endif
        if ( err != len )
        {
            printf("iguana_ramchain_offset.(%s): error.%ld writing len.%ld to fp.%p errno.%d\n",fname,err,(long)len,fp,errno);
            printf("probably out of disk space. please free up space\n");
            fprintf(stderr,"iguana_ramchain_sizefunc.(%s): error.%ld writing len.%ld to fp.%p errno.%d\n",fname,err,(long)len,fp,errno);
            fprintf(stderr,"probably out of disk space. please free up space\n");
            fpos = len = 0;
        }
        //else printf("fp.(%ld <- %d) ",ftell(fp),(int32_t)len);
    }
    (*offsetp) += len;
    return((void *)(long)((long)destptr + fpos));
}

int32_t iguana_ramchain_prefetch(struct iguana_info *coin,struct iguana_ramchain *ramchain,int32_t flag)
{
    RAMCHAIN_DECLARE; RAMCHAIN_ZEROES;
    struct iguana_pkhash p; struct iguana_unspent u; struct iguana_txid txid; uint32_t i,numpkinds,numtxids,numunspents,numexternal,tlen,plen,nonz=0; uint8_t *ptr;
//return(0);
    if ( ramchain->H.data != 0 )
    {
        if ( flag == 0 )
        {
            ptr = ramchain->fileptr;
            for (i=0; i<ramchain->filesize; i++)
                if ( ptr[i] != 0 )
                    nonz++;
        }
        else if ( (flag & 1) != 0 )
        {
            //printf("nonz.%d of %d\n",nonz,(int32_t)ramchain->filesize);
            X = RAMCHAIN_PTR(ramchain->H.data,Xoffset);
            T = RAMCHAIN_PTR(ramchain->H.data,Toffset);
            TXbits = RAMCHAIN_PTR(ramchain->H.data,TXoffset);
            //X = (void *)(long)((long)ramchain->H.data + ramchain->H.data->Xoffset);
            //T = (void *)(long)((long)ramchain->H.data + ramchain->H.data->Toffset);
            //TXbits = (void *)(long)((long)ramchain->H.data + ramchain->H.data->TXoffset);
            numtxids = ramchain->H.data->numtxids;
            numexternal = ramchain->H.data->numexternaltxids;
            tlen = (ramchain->H.data->numtxsparse * ramchain->H.data->txsparsebits) >> 3;
            for (i=0; i<numtxids; i++)
            {
                memcpy(&txid,&T[i],sizeof(txid));
                if ( bits256_nonz(txid.txid) != 0 )
                    nonz++;
            }
            /*for (i=0; i<numexternal; i++)
            {
                memcpy(&txid.txid,&X[i],sizeof(txid.txid));
                if ( bits256_nonz(txid.txid) != 0 )
                    nonz++;
            }*/
            for (i=0; i<tlen; i++)
                if ( TXbits[i] != 0 )
                    nonz++;
        }
        else if ( (flag & 2) != 0 )
        {
            U = RAMCHAIN_PTR(ramchain->H.data,Uoffset);
            //U = (void *)(long)((long)ramchain->H.data + ramchain->H.data->Uoffset);
            numunspents = ramchain->H.data->numunspents;
            for (i=0; i<numunspents; i++)
            {
                memcpy(&u,&U[i],sizeof(u));
                if ( u.value != 0 )
                    nonz++;
            }
        }
        else if ( (flag & 4) != 0 )
        {
            P = RAMCHAIN_PTR(ramchain->H.data,Poffset);
            PKbits = RAMCHAIN_PTR(ramchain->H.data,PKoffset);
            //P = (void *)(long)((long)ramchain->H.data + ramchain->H.data->Poffset);
            //PKbits = (void *)(long)((long)ramchain->H.data + ramchain->H.data->PKoffset);
            numpkinds = ramchain->H.data->numpkinds;
            plen = (ramchain->H.data->numpksparse * ramchain->H.data->pksparsebits) >> 3;
            for (i=0; i<numpkinds; i++)
            {
                memcpy(&p,&P[i],sizeof(p));
                if ( p.pkind != 0 )
                    nonz++;
            }
            for (i=0; i<plen; i++)
                if ( PKbits[i] != 0 )
                    nonz++;
        }
    }
    //printf("PREFETCH.[%d] flag.%d -> nonz.%d\n",ramchain->H.data->height,flag,nonz);
    return(nonz);
}

int64_t _iguana_rdata_action(char *fname,FILE *fp,bits256 lhashes[IGUANA_NUMLHASHES],void *destptr,uint64_t fpos,uint32_t expanded,uint32_t numtxids,uint32_t numunspents,uint32_t numspends,uint32_t numpkinds,uint32_t numexternaltxids,uint32_t scriptspace,uint32_t txsparsebits,uint64_t numtxsparse,uint32_t pksparsebits,uint64_t numpksparse,uint64_t srcsize,RAMCHAIN_FUNC,int32_t numblocks,uint8_t zcash)
{
#define RAMCHAIN_LARG(ind) ((lhashes == 0) ? 0 : lhashes[ind].bytes)
    FILE *fparg = 0; int32_t bROsize,iter; uint64_t txbits,pkbits,offset = 0; struct iguana_ramchaindata *rdata = destptr;
    if ( expanded != 0 )
    {
        if( txsparsebits == 0 || numtxsparse == 0 )
        {
            txsparsebits = hcalc_bitsize(numtxids);
            /*if ( txsparsebits < 8 )
                txsparsebits = 8;
            else if ( txsparsebits < 16 )
                txsparsebits = 16;
            else if ( txsparsebits < 32 )
                txsparsebits = 32;*/
            numtxsparse = SPARSECOUNT(numtxids);
        }
        if ( pksparsebits == 0 || numpksparse == 0 )
        {
            pksparsebits = hcalc_bitsize(numpkinds);
            /*if ( pksparsebits < 8 )
                pksparsebits = 8;
            else if ( pksparsebits < 16 )
                pksparsebits = 16;
            else if ( pksparsebits < 32 )
                pksparsebits = 32;*/
            numpksparse = SPARSECOUNT(numpkinds);
        }
        txbits = numtxsparse * txsparsebits; pkbits = numpksparse * pksparsebits;
    } else txbits = pkbits = numtxsparse = txsparsebits = numpksparse = pksparsebits = 0;
    for (iter=0; iter<2; iter++)
    {
        if ( iter == 0 && lhashes == 0 )
        {
            fparg = fp;
            continue;
        }
        offset = sizeof(struct iguana_ramchaindata);
        bROsize = (int32_t)(sizeof(struct iguana_blockRO) + zcash*sizeof(struct iguana_msgblockhdr_zcash));
        //printf("bROsize.%d\n",bROsize);
        B = iguana_ramchain_offset(fname,rdata,RAMCHAIN_LARG(IGUANA_LHASH_BLOCKS),fparg,fpos,B,&offset,(bROsize * numblocks),srcsize);
        T = iguana_ramchain_offset(fname,rdata,RAMCHAIN_LARG(IGUANA_LHASH_TXIDS),fparg,fpos,T,&offset,(sizeof(struct iguana_txid) * numtxids),srcsize);
        if ( expanded != 0 )
        {
            U = destptr, S = destptr;
            Ux = iguana_ramchain_offset(fname,rdata,RAMCHAIN_LARG(IGUANA_LHASH_UNSPENTS),fparg,fpos,Ux,&offset,(sizeof(struct iguana_unspent) * numunspents),srcsize);
            Sx = iguana_ramchain_offset(fname,rdata,RAMCHAIN_LARG(IGUANA_LHASH_SPENDS),fparg,fpos,Sx,&offset,(sizeof(struct iguana_spend) * numspends),srcsize);
            P = iguana_ramchain_offset(fname,rdata,RAMCHAIN_LARG(IGUANA_LHASH_PKHASHES),fparg,fpos,P,&offset,(sizeof(struct iguana_pkhash) * numpkinds),srcsize);
            //U2 = iguana_ramchain_offset(fname,rdata,RAMCHAIN_LARG(IGUANA_LHASH_SPENTINDS),fparg,fpos,U2,&offset,(sizeof(struct iguana_Uextra) * numunspents),srcsize);
            //P2 = 0;//iguana_ramchain_offset(fname,rdata,RAMCHAIN_LARG(IGUANA_LHASH_FIRSTSPENDS),fparg,fpos,P2,&offset,(sizeof(struct iguana_pkextra) * numpkinds),srcsize);
            A = iguana_ramchain_offset(fname,rdata,RAMCHAIN_LARG(IGUANA_LHASH_ACCOUNTS),fparg,fpos,A,&offset,(sizeof(struct iguana_account) * numpkinds),srcsize);
            char str[65];
            if ( 0 && X != 0 )
                printf("%p X[1] -> %s\n",&X[1],bits256_str(str,X[1]));
            X = iguana_ramchain_offset(fname,rdata,RAMCHAIN_LARG(IGUANA_LHASH_EXTERNALS),fparg,fpos,X,&offset,(sizeof(bits256) * numexternaltxids),srcsize);
            TXbits = iguana_ramchain_offset(fname,rdata,RAMCHAIN_LARG(IGUANA_LHASH_TXBITS),fparg,fpos,TXbits,&offset,hconv_bitlen(txbits),srcsize);
            PKbits = iguana_ramchain_offset(fname,rdata,RAMCHAIN_LARG(IGUANA_LHASH_PKBITS),fparg,fpos,PKbits,&offset,hconv_bitlen(pkbits),srcsize);
        }
        else
        {
            Ux = destptr, Sx = destptr, P = destptr, A = destptr, X = destptr, TXbits = destptr, PKbits = destptr, Kspace = destptr; //U2 = destptr, P2 = destptr,
            U = iguana_ramchain_offset(fname,rdata,RAMCHAIN_LARG(IGUANA_LHASH_UNSPENTS),fparg,fpos,U,&offset,(sizeof(struct iguana_unspent20) * numunspents),srcsize);
            if ( 0 && lhashes != 0 )
                printf("iter.%d lhashes.%p offset.%ld destptr.%p len.%ld fparg.%p fpos.%ld srcsize.%ld\n",iter,RAMCHAIN_LARG(IGUANA_LHASH_SPENDS),(long)offset,destptr,(long)sizeof(struct iguana_spend256) * numspends,fparg,(long)fpos,(long)srcsize);
            S = iguana_ramchain_offset(fname,rdata,RAMCHAIN_LARG(IGUANA_LHASH_SPENDS),fparg,fpos,S,&offset,(sizeof(struct iguana_spend256) * numspends),srcsize);
        }
        Kspace = iguana_ramchain_offset(fname,rdata,RAMCHAIN_LARG(IGUANA_LHASH_KSPACE),fparg,fpos,Kspace,&offset,scriptspace,srcsize); // at the end so it can be truncated
        if ( (fparg= fp) == 0 )
            break;
        lhashes = 0;
    }
    if ( rdata != 0 )
    {
        rdata->allocsize = offset;
        rdata->Boffset = (uint64_t)((long)B - (long)destptr);
        rdata->Toffset = (uint64_t)((long)T - (long)destptr);
        if ( expanded != 0 )
        {
            rdata->Uoffset = (uint64_t)((long)Ux - (long)destptr);
            rdata->Soffset = (uint64_t)((long)Sx - (long)destptr);
        }
        else
        {
            rdata->Uoffset = (uint64_t)((long)U - (long)destptr);
            rdata->Soffset = (uint64_t)((long)S - (long)destptr);
        }
        rdata->Koffset = (uint64_t)((long)Kspace - (long)destptr);
        rdata->scriptspace = (uint32_t)(offset - rdata->Koffset);
        rdata->Poffset = (uint64_t)((long)P - (long)destptr);
        //rdata->U2offset = (uint64_t)((long)U2 - (long)destptr);
        //rdata->P2offset = (uint64_t)((long)P2 - (long)destptr);
        rdata->Aoffset = (uint64_t)((long)A - (long)destptr);
        rdata->Xoffset = (uint64_t)((long)X - (long)destptr);
        rdata->TXoffset = (uint64_t)((long)TXbits - (long)destptr);
        rdata->PKoffset = (uint64_t)((long)PKbits - (long)destptr);
        rdata->numtxids = numtxids;
        rdata->numunspents = numunspents;
        rdata->numspends = numspends;
        rdata->numpkinds = numpkinds;
        rdata->numexternaltxids = numexternaltxids;
        rdata->txsparsebits = txsparsebits, rdata->numtxsparse = (uint32_t)numtxsparse;
        rdata->pksparsebits = pksparsebits, rdata->numpksparse = (uint32_t)numpksparse;
    }
    return(offset);
#undef RAMCHAIN_LARG
#undef SPARSECOUNT
}

int64_t iguana_ramchain_action(char *fname,RAMCHAIN_FUNC,FILE *fp,bits256 lhashes[IGUANA_NUMLHASHES],struct iguana_ramchaindata *destdata,uint64_t fpos,struct iguana_ramchaindata *srcdata,int32_t numblocks,int32_t scriptspace,uint8_t zcash)
{
    if ( 0 && ramchain->expanded == 0 )
        printf("action.%p (%p %p %p) %ld allocated.%ld [%d:%d %d:%d]\n",srcdata,fp,lhashes,destdata,(long)fpos,(long)srcdata->allocsize,srcdata->txsparsebits,srcdata->numtxsparse,srcdata->pksparsebits,srcdata->numpksparse);
    return(_iguana_rdata_action(fname,fp,lhashes,destdata,fpos,ramchain->expanded,srcdata->numtxids,srcdata->numunspents,srcdata->numspends,srcdata->numpkinds,srcdata->numexternaltxids,scriptspace,srcdata->txsparsebits,srcdata->numtxsparse,srcdata->pksparsebits,srcdata->numpksparse,srcdata->allocsize,RAMCHAIN_ARG,numblocks,zcash));
}

int64_t iguana_ramchain_size(char *fname,RAMCHAIN_FUNC,int32_t numblocks,int32_t scriptspace,uint8_t zcash)
{
    int64_t allocsize;
    allocsize = iguana_ramchain_action(fname,RAMCHAIN_ARG,0,0,0,0,ramchain->H.data,numblocks,scriptspace,zcash);
    if ( 0 && ramchain->expanded != 0 )
        printf("%p iguana_ramchain_size.expanded.%d %u: Koffset.%u scriptoffset.%u stacksize.%u stackspace.%u [%u]\n",ramchain,ramchain->expanded,(int32_t)allocsize,(int32_t)ramchain->H.data->Koffset,(int32_t)ramchain->H.scriptoffset,(int32_t)ramchain->H.stacksize,(int32_t)ramchain->H.data->stackspace,scriptspace);
    return(allocsize);
}

long iguana_ramchain_setsize(char *fname,struct iguana_ramchain *ramchain,struct iguana_ramchaindata *srcdata,int32_t numblocks,uint8_t zcash)
{
    RAMCHAIN_DECLARE; RAMCHAIN_ZEROES; struct iguana_ramchaindata *rdata = ramchain->H.data;
    //B = 0, Ux = 0, Sx = 0, P = 0, A = 0, X = 0, Kspace = TXbits = PKbits = 0, U = 0, S = 0, T = 0; //U2 = 0, P2 = 0,
    rdata->numtxids = ramchain->H.txidind;
    rdata->numunspents = ramchain->H.unspentind;
    rdata->numspends = ramchain->H.spendind;
    rdata->numpkinds = ramchain->pkind;
    rdata->numexternaltxids = ramchain->externalind;
    rdata->scriptspace = ramchain->H.scriptoffset;
    rdata->stackspace = ramchain->H.stacksize;
    rdata->allocsize = iguana_ramchain_size(fname,RAMCHAIN_ARG,numblocks,rdata->scriptspace,zcash);
    if ( 0 && rdata->scriptspace != 0 )
        printf("iguana_ramchain_setsize: Koffset.%d scriptspace.%d stackspace.%d (scriptoffset.%d stacksize.%d) allocsize.%d\n",(int32_t)rdata->Koffset,(int32_t)rdata->scriptspace,(int32_t)rdata->stackspace,(int32_t)ramchain->H.scriptoffset,(int32_t)ramchain->H.stacksize,(int32_t)rdata->allocsize);
    ramchain->datasize = rdata->allocsize;
    return((long)rdata->allocsize);
}

int64_t iguana_ramchain_compact(char *fname,RAMCHAIN_FUNC,struct iguana_ramchaindata *destdata,struct iguana_ramchaindata *srcdata,int32_t numblocks,uint8_t zcash)
{
    //iguana_ramchain_setsize(ramchain,srcdata);
    return(iguana_ramchain_action(fname,RAMCHAIN_ARG,0,0,destdata,0,srcdata,numblocks,ramchain->H.scriptoffset,zcash));
}

bits256 iguana_ramchain_lhashes(char *fname,RAMCHAIN_FUNC,struct iguana_ramchaindata *destdata,struct iguana_ramchaindata *srcdata,int32_t numblocks,int32_t scriptspace,uint8_t zcash)
{
    iguana_ramchain_action(fname,RAMCHAIN_ARG,0,destdata->lhashes,0,0,srcdata,numblocks,scriptspace,zcash);
    memset(&destdata->sha256,0,sizeof(destdata->sha256));
    vcalc_sha256(0,destdata->sha256.bytes,(void *)destdata,sizeof(*destdata));
    return(destdata->sha256);
}

int64_t iguana_ramchain_saveaction(char *fname,RAMCHAIN_FUNC,FILE *fp,struct iguana_ramchaindata *rdata,int32_t numblocks,int32_t scriptspace,uint8_t zcash)
{
    long before,after;
    before = ftell(fp);
    iguana_ramchain_action(fname,RAMCHAIN_ARG,fp,0,rdata,0,rdata,numblocks,scriptspace,zcash);
    after = ftell(fp);
    if ( 0 && ramchain->expanded == 0 )
    {
        int32_t i; for (i=0; i<scriptspace&&i<25; i++)
            printf("%02x",Kspace[i]);
        printf(" SAVEACTION: K.%d:%ld rdata.%d DEST T.%d U.%d S.%d P.%d X.%d -> size.%ld %ld vs %ld %u\n",(int32_t)rdata->Koffset,(long)Kspace-(long)rdata,(int32_t)sizeof(*rdata),rdata->numtxids,rdata->numunspents,rdata->numspends,rdata->numpkinds,rdata->numexternaltxids,(long)rdata->allocsize,(long)iguana_ramchain_size(fname,RAMCHAIN_ARG,numblocks,scriptspace,zcash),after-before+sizeof(*rdata),scriptspace);
    }
    //printf("before.%ld after.%ld allocsize.%ld [%ld] %ld expanded.%d\n",before,after,(long)srcdata->allocsize,(long)ramchain->H.data->allocsize,(long)iguana_ramchain_size(ramchain),ramchain->expanded);
    return(after - before);
}

int64_t iguana_ramchain_init(char *fname,struct iguana_ramchain *ramchain,struct OS_memspace *mem,struct OS_memspace *hashmem,int32_t firsti,int32_t numtxids,int32_t numunspents,int32_t numspends,int32_t numpkinds,int32_t numexternaltxids,int32_t scriptspace,int32_t expanded,int32_t numblocks,uint8_t zcash)
{
    RAMCHAIN_DECLARE; RAMCHAIN_ZEROES; int64_t offset = 0; struct iguana_ramchaindata *rdata;
    //B = 0, Ux = 0, Sx = 0, P = 0, A = 0, X = 0, Kspace = TXbits = PKbits = 0, U = 0, S = 0, T = 0;
    if ( mem == 0 )
        return(0);
    memset(ramchain,0,sizeof(*ramchain));
    ramchain->expanded = (expanded != 0);
    if ( (ramchain->hashmem= hashmem) != 0 )
        iguana_memreset(hashmem);
    rdata = ramchain->H.data = mem->ptr;//, offset += sizeof(struct iguana_ramchaindata);
    if ( (rdata->firsti= firsti) != 0 )
    {
        numtxids++, numunspents++, numspends++;
        if ( numpkinds != 0 )
            numpkinds++;
    }
    if ( numexternaltxids == 0 )
        numexternaltxids = numspends;
    if ( numpkinds == 0 )
        numpkinds = numunspents;
    _iguana_rdata_action(fname,0,0,rdata,0,expanded,numtxids,numunspents,numspends,numpkinds,numexternaltxids,scriptspace,0,0,0,0,0,RAMCHAIN_ARG,numblocks,zcash);
    offset += rdata->allocsize;
    if ( 0 && expanded != 0 )
        printf("init T.%d U.%d S.%d P.%d X.%d -> %ld\n",numtxids,numunspents,numspends,numpkinds,numexternaltxids,(long)offset);
    if ( rdata->allocsize != iguana_ramchain_size(fname,RAMCHAIN_ARG,numblocks,scriptspace,zcash) )
    {
        printf("offset.%ld scriptspace.%d allocsize.%ld vs memsize.%ld\n",(long)offset,scriptspace,(long)rdata->allocsize,(long)iguana_ramchain_size(fname,RAMCHAIN_ARG,numblocks,scriptspace,zcash));
        exit(-1);
    }
    if ( offset <= mem->totalsize )
        iguana_memreset(mem);
    else
    {
        printf("offset.%ld vs memsize.%ld\n",(long)offset,(long)mem->totalsize);
        printf("NEED %ld realloc for totalsize %ld\n",(long)offset,(long)iguana_ramchain_size(fname,RAMCHAIN_ARG,numblocks,scriptspace,zcash));
        getchar();
        //exit(-1);
        iguana_mempurge(mem);
        iguana_meminit(mem,"ramchain",0,offset,0);
    }
    if ( rdata->allocsize > mem->totalsize )
    {
        printf("init.(%d %d %d %d %d) rdata->allocsize.%ld mem->totalsize.%ld hashmemsize.%ld\n",numtxids,numunspents,numspends,numpkinds,numexternaltxids,(long)rdata->allocsize,mem->totalsize,hashmem!=0?hashmem->totalsize:0);
        exit(-1);
    }
    return(offset);
}

int32_t iguana_ramchain_alloc(char *fname,struct iguana_info *coin,struct iguana_ramchain *ramchain,struct OS_memspace *mem,struct OS_memspace *hashmem,uint32_t numtxids,uint32_t numunspents,uint32_t numspends,uint32_t numpkinds,uint32_t numexternaltxids,uint32_t scriptspace,int32_t height,int32_t numblocks,uint8_t zcash)
{
    RAMCHAIN_DECLARE; RAMCHAIN_ZEROES; int64_t hashsize,allocsize,x;
    //B = 0, Ux = 0, Sx = 0, P = 0, A = 0, X = 0, Kspace = TXbits = PKbits = 0, U = 0, S = 0, T = 0;
    memset(ramchain,0,sizeof(*ramchain));
    ramchain->height = height;
    allocsize = _iguana_rdata_action(fname,0,0,0,0,1,numtxids,numunspents,numspends,numpkinds,numexternaltxids,scriptspace,0,0,0,0,0,RAMCHAIN_ARG,numblocks,zcash);
    if ( 0 && ramchain->expanded != 0 )
        printf("T.%d U.%d S.%d P.%d X.%d -> %ld\n",numtxids,numunspents,numspends,numpkinds,numexternaltxids,(long)allocsize);
    memset(mem,0,sizeof(*mem));
    memset(hashmem,0,sizeof(*hashmem));
    hashsize = iguana_hashmemsize(numtxids,numunspents,numspends,numpkinds,numexternaltxids,scriptspace);
    while ( 0 && (x= (myallocated(0,-1)+hashsize+allocsize + 65536)) > coin->MAXMEM )
    {
        char str[65],str2[65]; fprintf(stderr,"ht.%d wait for allocated %s < MAXMEM %s | elapsed %.2f minutes hashsize.%ld allocsize.%ld\n",height,mbstr(str,myallocated(0,-1)+hashsize+allocsize),mbstr(str2,coin->MAXMEM),(double)(time(NULL)-coin->startutc)/60.,(long)hashsize,(long)allocsize);
        sleep(13);
    }
    iguana_meminit(hashmem,"ramhashmem",0,hashsize,0);
    iguana_meminit(mem,"ramchain",0,allocsize + 65536,0);
    mem->alignflag = sizeof(uint32_t);
    hashmem->alignflag = sizeof(uint32_t);
    if ( iguana_ramchain_init(fname,ramchain,mem,hashmem,1,numtxids,numunspents,numspends,numpkinds,numexternaltxids,scriptspace,1,numblocks,zcash) == 0 )
        return(-1);
    return(0);
}

long iguana_ramchain_save(struct iguana_info *coin,RAMCHAIN_FUNC,uint32_t ipbits,bits256 hash2,bits256 prevhash2,int32_t bundlei,struct iguana_bundle *bp,uint8_t zcash)
{
    struct iguana_ramchaindata *rdata,tmp; char fname[1024]; long fpos = -1; int32_t hdrsi,checki; FILE *fp;
    if ( (rdata= ramchain->H.data) == 0 )
    {
        printf("ramchainsave no data ptr\n");
        return(-1);
    }
    if ( (checki= iguana_peerfname(coin,&hdrsi,ipbits==0?GLOBAL_DBDIR:GLOBAL_TMPDIR,fname,ipbits,hash2,prevhash2,ramchain->numblocks,1)) != bundlei || bundlei < 0 || bundlei >= coin->chain->bundlesize )
    {
        printf(" wont save.(%s) bundlei.%d != checki.%d\n",fname,bundlei,checki);
        return(-1);
    }
    OS_compatible_path(fname);
#ifdef __PNACL__
    //static portable_mutex_t mutex;
    //portable_mutex_lock(&mutex);
#endif
    if ( (fp= fopen(fname,"wb")) == 0 )
        printf("iguana_ramchain_save: couldnt create.(%s) errno.%d\n",fname,errno);
    else coin->peers->numfiles++;
    if ( fp != 0 )
    {
        fpos = ftell(fp);
        if ( ramchain->expanded != 0 )
            iguana_ramchain_lhashes(fname,RAMCHAIN_ARG,rdata,rdata,bp!=0?bp->n:1,ramchain->H.scriptoffset,zcash);
        tmp = *rdata;
        iguana_ramchain_compact(fname,RAMCHAIN_ARG,&tmp,rdata,bp!=0?bp->n:1,zcash);
        if ( 0 && ramchain->expanded != 0 )
            printf("compact.%s: Koffset.%d scriptoffset.%d stacksize.%d allocsize.%d\n",fname,(int32_t)ramchain->H.data->Koffset,ramchain->H.scriptoffset,ramchain->H.stacksize,(int32_t)ramchain->H.data->allocsize);
        if ( fwrite(&tmp,1,sizeof(tmp),fp) != sizeof(tmp) )
        {
            printf("ramchain_save error writing header.%s\n",fname);
            fpos = -1;
        } else iguana_ramchain_saveaction(fname,RAMCHAIN_ARG,fp,rdata,bp!=0?bp->n:1,ramchain->H.scriptoffset,zcash);
        *rdata = tmp;
        fclose(fp);
    }
#ifdef __PNACL__
    //portable_mutex_unlock(&mutex);
#endif
   return(fpos);
}

int32_t iguana_ramchain_verify(struct iguana_info *coin,struct iguana_ramchain *ramchain)
{
    RAMCHAIN_DECLARE; struct iguana_txid *t; struct iguana_unspent *u; struct iguana_pkhash *p;
    struct iguana_ramchaindata *rdata; int32_t k,pkind,vout; struct iguana_kvitem *ptr; bits256 txid;
    if ( (rdata= ramchain->H.data) == 0 )
        return(-100);
    _iguana_ramchain_setptrs(RAMCHAIN_PTRS,rdata);
    ramchain->pkind = ramchain->H.unspentind = ramchain->H.spendind = rdata->firsti;
    ramchain->externalind = ramchain->H.stacksize = 0;
    ramchain->H.scriptoffset = 1;
    for (ramchain->H.txidind=rdata->firsti; ramchain->H.txidind<rdata->numtxids; ramchain->H.txidind++)
    {
        t = &T[ramchain->H.txidind];
        if ( t->txidind != ramchain->H.txidind )
        {
            printf("firsti.%d  t->txidind.%d != txidind.%d\n",rdata->firsti,t->txidind,ramchain->H.txidind);
            return(-1);
        }
        if ( t->firstvout != ramchain->H.unspentind )
        {
            printf("%p txidind.%d firstvout.%d != unspentind.%d\n",t,ramchain->H.txidind,t->firstvout,ramchain->H.unspentind);
            //exit(-1);
            return(-4);
        }
        if ( t->firstvin != ramchain->H.spendind )
        {
            printf("t[%d] firstvin.%d vs spendind.%d\n",t->txidind,t->firstvin,ramchain->H.spendind);
            return(-5);
        }
        if ( ramchain->expanded != 0 )
        {
            if ( (ptr= iguana_hashfind(ramchain,'T',t->txid.bytes)) == 0 )
                return(-2);
            if ( ptr->hh.itemind != ramchain->H.txidind )
            {
                if ( strcmp(coin->symbol,"BTC") == 0 )
                {
                    bits256 duptxid,duptxid2;
                decode_hex(duptxid.bytes,sizeof(duptxid),"e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468"); // BTC.tx0: 91722, 91880
                    decode_hex(duptxid2.bytes,sizeof(duptxid2),"d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599"); // BTC.tx0 91812, 91842
                    if ( memcmp(duptxid.bytes,t->txid.bytes,sizeof(duptxid)) == 0 || memcmp(duptxid2.bytes,t->txid.bytes,sizeof(duptxid2)) == 0 )
                        printf("BIP 0 detected\n");
                    else
                    {
                        char str[65]; printf("error -3: %s itemind.%d vs txidind.%d | num.%d\n",bits256_str(str,t->txid),ptr->hh.itemind,ramchain->H.txidind,ramchain->H.data->numtxids);
                        return(-3);
                    }
                }
                else
                {
                    char str[65]; printf("error -3: %s itemind.%d vs txidind.%d | num.%d\n",bits256_str(str,t->txid),ptr->hh.itemind,ramchain->H.txidind,ramchain->H.data->numtxids);
                    //exit(-1);
                    return(-3);
                }
            }
            for (k=0; k<t->numvouts; k++,ramchain->H.unspentind++)
            {
                u = &Ux[ramchain->H.unspentind];
                if ( u->txidind != ramchain->H.txidind )
                {
                    printf("ramchain_verify k.%d %p U.%d u->txidind.%x != txidind.%d\n",k,u,ramchain->H.unspentind,u->txidind,ramchain->H.txidind);
                    //exit(-1);
                    return(-6);
                }
                if ( (pkind= u->pkind) < 0 || pkind >= rdata->numpkinds )
                {
                    printf("k.%d unspentind.%d pkind.%d numpkinds.%d\n",k,ramchain->H.unspentind,pkind,rdata->numpkinds);
                    return(-7);
                }
                p = &P[pkind];
                if ( (ptr= iguana_hashfind(ramchain,'P',p->rmd160)) == 0 )
                    return(-8);
                if ( ptr->hh.itemind != pkind )//&& p->firstunspentind > ramchain->H.unspentind )
                {
                    printf("%p itemind.%d pkind.%d %d unspentind?\n",p,ptr->hh.itemind,pkind,ramchain->H.unspentind);
                    return(-9);
                }
            }
        }
        else
        {
            for (k=0; k<t->numvouts; k++,ramchain->H.unspentind++)
            {
                if ( U[ramchain->H.unspentind].txidind != ramchain->H.txidind )
                {
                    printf(" k.%d U.%d u->txidind.%x != txidind.%d\n",k,ramchain->H.unspentind,U[ramchain->H.unspentind].txidind,ramchain->H.txidind);
                    return(-6);
                }
            }
        }
        ramchain->H.spendind += t->numvins;
    }
    ramchain->H.spendind = rdata->firsti;
    for (ramchain->H.txidind=rdata->firsti; ramchain->H.txidind<rdata->numtxids; ramchain->H.txidind++)
    {
        t = &T[ramchain->H.txidind];
        for (k=0; k<t->numvins; k++,ramchain->H.spendind++)
        {
            if ( ramchain->expanded != 0 )
            {
                //printf("item.%p [%d] X.%p k.%d txidind.%d/%d spendind.%d/%d s->txidind.%x/v%d\n",rdata,rdata->numexternaltxids,X,k,ramchain->txidind,rdata->numtxids,spendind,rdata->numspends,s->spendtxidind,s->vout);
                if ( (vout= iguana_ramchain_txid(coin,RAMCHAIN_ARG,&txid,&Sx[ramchain->H.spendind])) < -1 )
                {
                    printf("txidind.%d k.%d error getting txid firsti.%d X.%d vout.%d spend.%x/%d numX.%d numT.%d\n",ramchain->H.txidind,k,rdata->firsti,ramchain->externalind,vout,Sx[ramchain->H.spendind].spendtxidind,rdata->numspends,rdata->numexternaltxids,rdata->numtxids);
                    return(-10);
                }
                if ( vout == -1 )
                {
                    // mining output
                }
                else
                {
                    if ( (ptr= iguana_hashfind(ramchain,'T',txid.bytes)) == 0 )
                    {
                        char str[65]; printf("cant find vout.%d %s\n",vout,bits256_str(str,txid));
                        return(-11);
                    }
                }
            }
        }
    }
    if ( ramchain->expanded != 0 && ramchain->A != ramchain->creditsA )
    {
        for (k=rdata->firsti; k<rdata->numpkinds; k++)
        {
            if ( memcmp(&ramchain->A[k],&ramchain->creditsA[k],sizeof(ramchain->A[k])) != 0 )
            {
                printf("k.%d balance.(%.8f vs %.8f) lastU.(%d %d)\n",k,dstr(ramchain->A[k].total),dstr(ramchain->creditsA[k].total),ramchain->A[k].lastunspentind,ramchain->creditsA[k].lastunspentind);
                //return(-14);
            }
            //if ( memcmp(&ramchain->P2[k],&ramchain->roP2[k],sizeof(ramchain->P2[k])) != 0 )
            //    return(-15);
        }
        //for (k=rdata->firsti; k<rdata->numunspents; k++)
        //    if ( memcmp(&ramchain->U2[k],&ramchain->roU2[k],sizeof(ramchain->U2[k])) != 0 )
        //        return(-16);
    }
    return(0);
}

int32_t iguana_ramchain_free(struct iguana_info *coin,struct iguana_ramchain *ramchain,int32_t deleteflag)
{
    struct iguana_kvitem *item,*tmp;
    if ( ramchain->H.ROflag != 0 && ramchain->hashmem == 0 )
    {
        if ( ramchain->A != ramchain->creditsA )
        {
            //printf("hashmem.%p Free A %p %p, numpkinds.%d %ld\n",ramchain->hashmem,ramchain->A,ramchain->creditsA,ramchain->H.data->numpkinds,sizeof(*ramchain->A) * ramchain->H.data->numpkinds);
            if ( deleteflag != 0 )
                myfree(ramchain->A,sizeof(*ramchain->A) * ramchain->H.data->numpkinds), ramchain->A = 0;
        }
        //if ( ramchain->U2 != ramchain->roU2 )
        //    myfree(ramchain->U2,sizeof(*ramchain->U2) * ramchain->H.data->numunspents), ramchain->U2 = 0;
        //if ( ramchain->P2 != ramchain->roP2 )
        //    myfree(ramchain->P2,sizeof(*ramchain->P2) * ramchain->H.data->numpkinds), ramchain->P2 = 0;
    }
    if ( deleteflag != 0 )
    {
        if ( ramchain->txids != 0 )
        {
            HASH_ITER(hh,ramchain->txids,item,tmp)
            {
                HASH_DEL(ramchain->txids,item);
                if ( ramchain->hashmem == 0 )
                    myfree(item,sizeof(*item));
            }
        }
        if ( ramchain->pkhashes != 0 )
        {
            HASH_ITER(hh,ramchain->pkhashes,item,tmp)
            {
                HASH_DEL(ramchain->pkhashes,item);
                if ( ramchain->hashmem == 0 )
                    myfree(item,sizeof(*item));
            }
        }
        if ( ramchain->txbits != 0 )
        {
            free(ramchain->txbits);
            ramchain->txbits = 0;
        }
        if ( ramchain->cacheT != 0 )
        {
            free(ramchain->cacheT);
            ramchain->cacheT = 0;
        }
    }
    ramchain->txids = 0;
    ramchain->pkhashes = 0;
    if ( ramchain->hashmem != 0 )
        iguana_mempurge(ramchain->hashmem), ramchain->hashmem = 0;
    if ( ramchain->filesize != 0 )
    {
        munmap(ramchain->fileptr,ramchain->filesize);
        ramchain->fileptr = 0;
        ramchain->filesize = 0;
    }
    if ( ramchain->Xspendptr != 0 )
    {
        munmap(ramchain->Xspendptr,ramchain->filesize);
        ramchain->Xspendptr = 0;
        ramchain->numXspends = 0;
        ramchain->Xspendinds = 0;
    }
    //iguana_volatilespurge(coin,ramchain);
    if ( deleteflag != 0 )
        memset(ramchain,0,sizeof(*ramchain));
    return(0);
}

int32_t iguana_bundleremove(struct iguana_info *coin,int32_t hdrsi,int32_t tmpfiles)
{
    struct iguana_bundle *bp; int32_t i; char fname[1024],str[65];
    if ( hdrsi >= 0 && hdrsi < coin->bundlescount && (bp= coin->bundles[hdrsi]) != 0 )
    {
        printf("delete bundle.[%d]\n",hdrsi);
        if ( tmpfiles != 0 )
        {
            for (i=0; i<bp->n; i++)
                iguana_blockunmark(coin,bp->blocks[i],bp,i,1);
        }
        iguana_ramchain_free(coin,&bp->ramchain,0);
        if ( iguana_bundlefname(coin,bp,fname) == 0 )
            OS_removefile(fname,0);
        sprintf(fname,"%s/%s/spends/%s.%d",GLOBAL_DBDIR,coin->symbol,bits256_str(str,bp->hashes[0]),bp->bundleheight), OS_removefile(fname,0);
        sprintf(fname,"%s/%s/accounts/debits.%d",GLOBAL_DBDIR,coin->symbol,bp->bundleheight), OS_removefile(fname,0);
        sprintf(fname,"%s/%s/accounts/lastspends.%d",GLOBAL_DBDIR,coin->symbol,bp->bundleheight), OS_removefile(fname,0);
        sprintf(fname,"%s/%s/validated/%d",GLOBAL_DBDIR,coin->symbol,bp->bundleheight), OS_removefile(fname,0);
        bp->utxofinish = bp->startutxo = bp->balancefinish = bp->validated = bp->emitfinish = bp->converted = 0;
        return(0);
    }
    return(-1);
}

int32_t iguana_ramchain_extras(struct iguana_info *coin,struct iguana_ramchain *ramchain,struct OS_memspace *hashmem,int32_t extraflag)
{
    RAMCHAIN_DECLARE; int32_t err=0; 
    if ( ramchain->expanded != 0 )
    {
        _iguana_ramchain_setptrs(RAMCHAIN_PTRS,ramchain->H.data);
        if ( extraflag == 0 && ramchain->H.data != 0 )
        {
            if ( (ramchain->hashmem= hashmem) != 0 )
                iguana_memreset(hashmem);
            else printf("alloc ramchain->A %d\n",(int32_t)(sizeof(struct iguana_account) * ramchain->H.data->numpkinds));
            ramchain->A = (hashmem != 0 && hashmem->ptr != 0) ? iguana_memalloc(hashmem,sizeof(struct iguana_account) * ramchain->H.data->numpkinds,1) : mycalloc('p',ramchain->H.data->numpkinds,sizeof(struct iguana_account));
            ramchain->Uextras = (hashmem != 0 && hashmem->ptr != 0) ? iguana_memalloc(hashmem,sizeof(*ramchain->Uextras) * ramchain->H.data->numunspents,1) : mycalloc('p',ramchain->H.data->numunspents,sizeof(*ramchain->Uextras));
        } else err = iguana_volatilesmap(coin,ramchain);
    }
    return(err);
}

int32_t iguana_Xspendmap(struct iguana_info *coin,struct iguana_ramchain *ramchain,struct iguana_bundle *bp)
{
    int32_t iter; bits256 sha256; char str[65],fname[1024]; void *ptr; long filesize;
    for (iter=0; iter<2; iter++)
    {
        sprintf(fname,"%s/%s%s/spends/%s.%d",GLOBAL_DBDIR,iter==0?"ro/":"",coin->symbol,bits256_str(str,bp->hashes[0]),bp->bundleheight);
        if ( (ptr= OS_mapfile(fname,&filesize,0)) != 0 )
        {
            ramchain->Xspendinds = (void *)((long)ptr + sizeof(sha256));
            if ( bp->Xvalid == 0 )
                vcalc_sha256(0,sha256.bytes,(void *)ramchain->Xspendinds,(int32_t)(filesize - sizeof(sha256)));
            ramchain->from_roX = (iter == 0);
            if ( bp->Xvalid != 0 || memcmp(sha256.bytes,ptr,sizeof(sha256)) == 0 )
            {
                ramchain->Xspendptr = ptr;
                ramchain->numXspends = (int32_t)((filesize - sizeof(sha256)) / sizeof(*ramchain->Xspendinds));
                bp->startutxo = bp->utxofinish = (uint32_t)time(NULL);
                if ( bp->Xvalid == 0 )
                {
                    printf("[%d] filesize %ld Xspendptr.%p %p num.%d\n",bp->hdrsi,filesize,ramchain->Xspendptr,ramchain->Xspendinds,ramchain->numXspends);
                    bp->Xvalid = 1;
                }
                return(ramchain->numXspends);
                //int32_t i; for (i=0; i<ramchain->numXspends; i++)
                //    printf("(%d u%d) ",ramchain->Xspendinds[i].hdrsi,ramchain->Xspendinds[i].ind);
                //printf("mapped utxo vector[%d] from (%s)\n",ramchain->numXspends,fname);
            }
            else
            {
                char str[65]; printf("hash cmp error.%d vs (%s)\n",memcmp(sha256.bytes,ptr,sizeof(sha256)),bits256_str(str,sha256));
                munmap(ptr,filesize);
                ramchain->Xspendinds = 0;
            }
        }
    }
    return(ramchain->numXspends);
}

struct iguana_ramchain *_iguana_ramchain_map(struct iguana_info *coin,char *fname,struct iguana_bundle *bp,int32_t numblocks,struct iguana_ramchain *ramchain,struct OS_memspace *hashmem,uint32_t ipbits,bits256 hash2,bits256 prevhash2,int32_t bundlei,long fpos,int32_t allocextras,int32_t expanded,uint8_t zcash)
{
    RAMCHAIN_DECLARE; int32_t valid,iter,i,checki,hdrsi; long filesize; void *ptr;
    char str[65],str2[65],dirstr[64]; struct iguana_block *block; struct iguana_blockRO *bRO;
    /*if ( ramchain->expanded != 0 && (ramchain->sigsfileptr == 0 || ramchain->sigsfilesize == 0) )
    {
        sprintf(sigsfname,"sigs/%s/%s",coin->symbol,bits256_str(str,hash2));
        if ( (ramchain->sigsfileptr= OS_mapfile(sigsfname,&ramchain->sigsfilesize,0)) == 0 )
        {
            printf("couldnt map.(%s)\n",sigsfname);
            return(0);
        }
    }*/
    if ( ramchain->fileptr == 0 || ramchain->filesize <= 0 )
    {
        for (iter=0; iter<2; iter++)
        {
            strcpy(dirstr,GLOBAL_DBDIR);
            if ( iter == 0 )
                strcat(dirstr,"/ro");
            if ( (checki= iguana_peerfname(coin,&hdrsi,ipbits==0?dirstr:GLOBAL_TMPDIR,fname,ipbits,hash2,prevhash2,numblocks,1)) != bundlei || bundlei < 0 || bundlei >= coin->chain->bundlesize )
            {
                printf("iguana_ramchain_map.(%s) illegal hdrsi.%d bundlei.%d %s\n",fname,hdrsi,bundlei,bits256_str(str,hash2));
                continue;
            }
            memset(ramchain,0,sizeof(*ramchain));
            if ( (ptr= OS_mapfile(fname,&filesize,0)) == 0 )
                continue;
            ramchain->from_ro = (iter == 0);
            ramchain->fileptr = ptr;
            ramchain->filesize = (long)filesize;
            if ( (ramchain->hashmem= hashmem) != 0 )
                iguana_memreset(hashmem);
            break;
        }
        if ( ramchain->fileptr == 0 )
            return(0);
    }
    if ( ramchain->fileptr != 0 && ramchain->filesize > 0 )
    {
        // verify hashes
        ramchain->H.data = (void *)(long)((long)ramchain->fileptr + fpos);
        ramchain->H.ROflag = 1;
        ramchain->expanded = expanded;
        ramchain->numblocks = (bp == 0) ? 1 : bp->n;
        //printf("ptr.%p exp.%d extra.%d %p mapped P[%d] fpos.%d + %ld -> %ld vs %ld offset.%u:%u stack.%u:%u\n",ptr,expanded,allocextras,ramchain->H.data,(int32_t)ramchain->H.data->Poffset,(int32_t)fpos,(long)ramchain->H.data->allocsize,(long)(fpos + ramchain->H.data->allocsize),ramchain->filesize,ramchain->H.scriptoffset,ramchain->H.data->scriptspace,ramchain->H.stacksize,ramchain->H.data->stackspace);
        if ( 0 && bp != 0 )
        {
            /*blocksRO = (struct iguana_blockRO *)ramchain->H.data;
            for (i=0; i<bp->n; i++)
            {
                printf("%p ",&blocksRO[i]);
                bp->hashes[i] = blocksRO[i].hash2;
                if ( (bp->blocks[i]= iguana_blockhashset(coin,-1,blocksRO[i].hash2,1)) == 0 )
             {
             printf("Error getting blockptr\n");
             return(0);
             }
             bp->blocks[i]->RO = blocksRO[i];
             }
             ramchain->H.data = (void *)&blocksRO[bp->n];*/
             for (valid=0,i=bp->n-1; i>=0; i--)
             {
                if ( (block= bp->blocks[i]) != 0 )
                {
                    if ( memcmp(block->RO.hash2.bytes,bp->hashes[i].bytes,sizeof(block->RO.hash2)) == 0 )
                    {
                        if ( i == 0 || memcmp(block->RO.prev_block.bytes,bp->hashes[i-1].bytes,sizeof(block->RO.prev_block)) == 0 )
                            valid++;
                    }
                }
            }
            if ( valid != bp->n )
            {
                printf("valid.%d != bp->n.%d, reject mapped ramchain\n",valid,bp->n);
                return(0);
            }
        }
        _iguana_ramchain_setptrs(RAMCHAIN_PTRS,ramchain->H.data);
        if ( iguana_ramchain_size(fname,RAMCHAIN_ARG,ramchain->numblocks,ramchain->H.data->scriptspace,zcash) != ramchain->H.data->allocsize || fpos+ramchain->H.data->allocsize > filesize )
        {
            printf("iguana_ramchain_map.(%s) size mismatch %ld vs %ld vs filesize.%ld numblocks.%d expanded.%d fpos.%d sum %ld\n",fname,(long)iguana_ramchain_size(fname,RAMCHAIN_ARG,ramchain->numblocks,ramchain->H.data->scriptspace,zcash),(long)ramchain->H.data->allocsize,(long)filesize,ramchain->numblocks,expanded,(int32_t)fpos,(long)(fpos+ramchain->H.data->allocsize));
            //exit(-1);
            munmap(ramchain->fileptr,ramchain->filesize);
            OS_removefile(fname,0);
            return(0);
        }
        else if ( memcmp(hash2.bytes,ramchain->H.data->firsthash2.bytes,sizeof(bits256)) != 0 )
        {
            printf("iguana_ramchain_map.(%s) hash2 mismatch %s vs %s\n",fname,bits256_str(str,hash2),bits256_str(str2,ramchain->H.data->firsthash2));
            //munmap(ramchain->fileptr,ramchain->filesize);
            return(0);
        }
        else if ( ramchain->expanded != 0 )
        {
            if ( allocextras > 0 )
            {
                ramchain->height = ramchain->H.data->height;
                if ( iguana_ramchain_extras(coin,ramchain,ramchain->hashmem,allocextras) == 0 && bp != 0 )
                {
                    bp->balancefinish = (uint32_t)time(NULL);
                    //printf("found balances for %d\n",bp->hdrsi);
                } //else printf("error with extras\n");
            }
        }
        if ( B != 0 && bp != 0 )
        {
            int32_t bROsize = (int32_t)(sizeof(struct iguana_blockRO) + coin->chain->zcash*sizeof(struct iguana_msgblockhdr_zcash));
            for (i=0; i<bp->n; i++)
            {
                bRO = (void *)((long)B + i*bROsize);
                if ( bp->blocks[i] == 0 &&  (bp->blocks[i]= iguana_blockhashset("mapchain",coin,-1,bRO->hash2,1)) == 0 )
                {
                    printf("Error getting blockptr\n");
                    return(0);
                }
                memcpy(&bp->blocks[i]->RO,bRO,bROsize);//coin->blocks.RO[bp->bundleheight + i];
                //coin->blocks.RO[bp->bundleheight+i] = B[i];
                bp->hashes[i] = bRO->hash2;
            }
        }
        //printf("iguana_ramchain_map.(%s) size %ld vs %ld vs filesize.%ld numblocks.%d expanded.%d fpos.%d sum %ld\n",fname,(long)iguana_ramchain_size(RAMCHAIN_ARG,ramchain->numblocks,ramchain->H.data->scriptspace),(long)ramchain->H.data->allocsize,(long)filesize,ramchain->numblocks,expanded,(int32_t)fpos,(long)(fpos+ramchain->H.data->allocsize));
        bp->Xvalid = 1;
        iguana_Xspendmap(coin,ramchain,bp);
        return(ramchain);
    } else printf("iguana_ramchain_map.(%s) cant map file\n",fname);
    return(0);
}

struct iguana_ramchain *iguana_ramchain_map(struct iguana_info *coin,char *fname,struct iguana_bundle *bp,int32_t numblocks,struct iguana_ramchain *ramchain,struct OS_memspace *hashmem,uint32_t ipbits,bits256 hash2,bits256 prevhash2,int32_t bundlei,long fpos,int32_t allocextras,int32_t expanded)
{
    struct iguana_ramchain *retptr;
#ifdef __PNACL__
    //static portable_mutex_t mutex;
    //portable_mutex_lock(&mutex);
#endif
    ramchain->height = bp->bundleheight;
    retptr = _iguana_ramchain_map(coin,fname,bp,numblocks,ramchain,hashmem,ipbits,hash2,prevhash2,bundlei,fpos,allocextras,expanded,coin->chain->zcash);
#ifdef __PNACL__
    //portable_mutex_unlock(&mutex);
#endif
    return(retptr);
}

void iguana_ramchain_link(struct iguana_ramchain *ramchain,bits256 firsthash2,int32_t hdrsi,int32_t height,int32_t bundlei,int32_t numblocks,int32_t firsti,int32_t ROflag)
{
    if ( ROflag == 0 )
    {
        ramchain->H.data->firsthash2 = firsthash2;
        //ramchain->H.data->lasthash2 = lasthash2;
        ramchain->H.data->hdrsi = hdrsi;
        ramchain->H.data->height = height;
        ramchain->H.data->numblocks = numblocks;
    }
    ramchain->H.hdrsi = hdrsi;
    ramchain->H.bundlei = bundlei;
    ramchain->height = height;
    ramchain->numblocks = numblocks;
    //ramchain->lasthash2 = lasthash2;
    ramchain->H.txidind = ramchain->H.unspentind = ramchain->H.spendind = ramchain->pkind = firsti;
    ramchain->externalind = 0;//ramchain->H.scriptoffset = ramchain->H.stacksize = 0;
}

int32_t iguana_ramchain_cmp(struct iguana_ramchain *A,struct iguana_ramchain *B,int32_t deepflag)
{
    int32_t i; char str[65],str2[65];
    struct iguana_txid *Ta,*Tb; struct iguana_unspent20 *Ua,*Ub; struct iguana_spend256 *Sa,*Sb;
    struct iguana_pkhash *Pa,*Pb; bits256 *Xa,*Xb; struct iguana_blockRO *Ba,*Bb;
    struct iguana_account *ACCTa,*ACCTb; struct iguana_unspent *Uxa,*Uxb;
    struct iguana_spend *Sxa,*Sxb; uint8_t *TXbitsa,*TXbitsb,*PKbitsa,*PKbitsb,*Kspacea,*Kspaceb;
    
    if ( A->H.data != 0 && B->H.data != 0 && A->H.data->numblocks == B->H.data->numblocks && memcmp(A->H.data->firsthash2.bytes,B->H.data->firsthash2.bytes,sizeof(A->H.data->firsthash2)) == 0 )
    {
        if ( A->H.data->firsti == B->H.data->firsti && A->H.data->numtxids == B->H.data->numtxids && A->H.data->numunspents == B->H.data->numunspents && A->H.data->numspends == B->H.data->numspends && A->H.data->numpkinds == B->H.data->numpkinds && A->H.data->numexternaltxids == B->H.data->numexternaltxids )
        {
            _iguana_ramchain_setptrs(A,&Ba,&Ta,&Ua,&Sa,&Pa,&ACCTa,&Xa,&Uxa,&Sxa,&TXbitsa,&PKbitsa,&Kspacea,A->H.data);
            _iguana_ramchain_setptrs(B,&Bb,&Tb,&Ub,&Sb,&Pb,&ACCTb,&Xb,&Uxb,&Sxb,&TXbitsb,&PKbitsb,&Kspaceb,B->H.data);
            for (i=A->H.data->firsti; i<A->H.data->numtxids; i++)
                if ( memcmp(&Ta[i],&Tb[i],sizeof(Ta[i])) != 0 )
                    return(-2);
            if ( A->numblocks > 0 )
            {
                if ( A->expanded != 0 )
                {
                for (i=A->H.data->firsti; i<A->H.data->numspends; i++)
                    if ( memcmp(&Sxa[i],&Sxb[i],sizeof(Sxa[i])) != 0 )
                        return(-3);
                /*for (i=A->H.data->firsti; i<A->H.data->numunspents; i++)
                {break;
                    int32_t j,metalen,checklen; uint8_t _script[8129],*checkscript;
                    if ( memcmp(&Uxa[i],&Uxb[i],sizeof(Uxa[i])) != 0 )
                        return(-4);
                    checkscript = iguana_ramchain_scriptdecode(&metalen,&checklen,Kspacea,Uxa[i].type,_script,Uxa[i].scriptoffset,0);
                    for (j=0; j<checklen; j++)
                        printf("%02x",checkscript[j]);
                    printf(" checkscript.%d meta.%d\n",checklen,metalen);
                    //if ( memcmp(&U2a[i],&U2b[i],sizeof(U2a[i])) != 0 )
                    //    return(-5);
                }*/
                for (i=A->H.data->firsti; i<A->H.data->numpkinds; i++)
                {
                    //if ( memcmp(&P2a[i],&P2b[i],sizeof(P2a[i])) != 0 )
                    //    return(-6);
                    if ( memcmp(&ACCTa[i],&ACCTb[i],sizeof(ACCTa[i])) != 0 )
                        return(-7);
                }
                for (i=0; i<A->H.data->numexternaltxids; i++)
                    if ( memcmp(&Xa[i],&Xb[i],sizeof(Xa[i])) != 0 )
                    {
                        bits256_str(str2,Xb[i]);
                        bits256_str(str,Xa[i]);
                        printf("X[%d] A.%s B.%s\n",i,str,str2);
                        return(-8);
                    }
                }
                else
                {
                    for (i=A->H.data->firsti; i<A->H.data->numspends; i++)
                        if ( memcmp(&Sa[i],&Sb[i],sizeof(Sa[i])) != 0 )
                            return(-9);
                    for (i=A->H.data->firsti; i<A->H.data->numunspents; i++)
                        if ( memcmp(&Ua[i],&Ub[i],sizeof(Ua[i])) != 0 )
                            return(-10);
                    /*for (i=A->H.data->firsti; i<A->H.data->numunspents; i++)
                    {break;
                        int32_t j,metalen,checklen; uint8_t _script[8129],*checkscript;
                        checkscript = iguana_ramchain_scriptdecode(&metalen,&checklen,Kspacea,Ua[i].type,_script,Ua[i].scriptoffset,0);
                        for (j=0; j<checklen; j++)
                            printf("%02x",checkscript[j]);
                        printf(" checkscript.%d meta.%d\n",checklen,metalen);
                        //if ( memcmp(&U2a[i],&U2b[i],sizeof(U2a[i])) != 0 )
                        //    return(-5);
                    }*/
                }
            }
            else
            {
            }
        }
        return(0);
    }
    printf("cmp %p %p, numblocks %d:%d %d:%d %s %s\n",A->H.data,B->H.data,A->numblocks,A->H.data->numblocks,B->numblocks,B->H.data->numblocks,bits256_str(str,A->H.data->firsthash2),bits256_str(str2,B->H.data->firsthash2));
    return(-1);
}

int32_t iguana_ramchain_iterate(struct iguana_info *coin,struct iguana_ramchain *dest,struct iguana_ramchain *ramchain,struct iguana_bundle *bp,int16_t bundlei)
{
    RAMCHAIN_DECLARE; RAMCHAIN_DESTDECLARE;
    int32_t j,hdrsi,prevout,scriptlen; uint32_t sequenceid,destspendind=0,desttxidind=0; uint16_t fileid; uint64_t scriptpos;
    bits256 prevhash; uint64_t value; uint8_t type; struct iguana_unspent *u;
    struct iguana_txid *tx; struct iguana_ramchaindata *rdata; uint8_t rmd160[20];
    //if ( dest != 0 )
    //    printf("iterate ramchain.%p rdata.%p dest.%p ht.%d/%d txids.%p destoffset.%d\n",ramchain,ramchain->H.data,dest,bp->bundleheight,bp->n,ramchain->txids,dest->H.scriptoffset);
    if ( (rdata= ramchain->H.data) == 0 )
    {
        printf("iguana_ramchain_iterate cant iterate without data\n");
        return(-1);
    }
    if ( dest != 0 )
        _iguana_ramchain_setptrs(RAMCHAIN_DESTPTRS,dest->H.data);
    //fprintf(stderr,"iterate %d/%d dest.%p ramchain.%p rdata.%p\n",bp->bundleheight,bp->n,dest,ramchain,rdata);
    _iguana_ramchain_setptrs(RAMCHAIN_PTRS,ramchain->H.data);
    ramchain->H.ROflag = 1;
    ramchain->H.unspentind = ramchain->H.spendind = ramchain->pkind = rdata->firsti;
    ramchain->externalind = ramchain->H.stacksize = 0;
    ramchain->H.scriptoffset = 1;
    if ( dest != 0 )
    {
        desttxidind = dest->H.txidind;
        destspendind = dest->H.spendind;
    }
    for (ramchain->H.txidind=rdata->firsti; ramchain->H.txidind<rdata->numtxids; ramchain->H.txidind++)
    {
        if ( coin->active == 0 )
            return(-1);;
        if ( 0 && ramchain->expanded == 0 && dest != 0 )
            printf("ITER [%d] TXID.%d -> dest.%p desttxid.%d dest->hashmem.%p numtxids.%d\n",ramchain->H.data->height,ramchain->H.txidind,dest,dest!=0?dest->H.txidind:0,dest!=0?dest->hashmem:0,rdata->numtxids);
        tx = &T[ramchain->H.txidind];
        if ( iguana_ramchain_addtxid(coin,RAMCHAIN_ARG,tx->txid,tx->numvouts,tx->numvins,tx->locktime,tx->version,tx->timestamp,bundlei) == 0 )
            return(-1);
        //printf("txidind.%u firstvout.%u firstvin.%u bundlei.%d n.%d\n",tx->txidind,tx->firstvout,tx->firstvin,bundlei,bp->n);
        if ( dest != 0 )
        {
            //char str[65];
            if ( 0 && ramchain->expanded == 0 )
                printf("ITER [%d] TXID.%d -> dest.%p desttxid.%d dest->hashmem.%p numtxids.%d\n",ramchain->H.data->height,ramchain->H.txidind,dest,dest!=0?dest->H.txidind:0,dest!=0?dest->hashmem:0,rdata->numtxids);
            if ( iguana_ramchain_addtxid(coin,RAMCHAIN_DESTARG,tx->txid,tx->numvouts,tx->numvins,tx->locktime,tx->version,tx->timestamp,bundlei) == 0 )
                return(-2);
        }
        for (j=0; j<tx->numvouts; j++)
        {
            if ( coin->active == 0 )
                return(-1);
            fileid = 0;
            scriptpos = 0;
            scriptlen = 0;
            memset(rmd160,0,sizeof(rmd160));
            if ( ramchain->H.unspentind < rdata->numunspents )
            {
                if ( ramchain->expanded != 0 )
                {
                    u = &Ux[ramchain->H.unspentind];
                    value = u->value;
                    hdrsi = u->hdrsi;
                    type = u->type;
                    fileid = u->fileid;
                    scriptpos = u->scriptpos;
                    scriptlen = u->scriptlen;
                    if ( u->pkind < rdata->numpkinds )
                    {
                        memcpy(rmd160,P[u->pkind].rmd160,20);
                        //printf("EXPANDED scriptpos.%u scriptlen.%d type.%d %.8f\n",(uint32_t)scriptpos,scriptlen,type,dstr(value));
                        /*scriptlen = 0;
                        if ( u->scriptoffset != 0 || type == IGUANA_SCRIPT_76AC )
                        {
                            scriptdata = iguana_ramchain_scriptdecode(&metalen,&scriptlen,Kspace,type,_script,u->scriptoffset,P[u->pkind].pubkeyoffset < ramchain->H.scriptoffset ? P[u->pkind].pubkeyoffset : 0);
                        }*/
                        //fprintf(stderr,"iter add %p[%d] type.%d\n",scriptdata,scriptlen,type);
                        if ( iguana_ramchain_addunspent(coin,RAMCHAIN_ARG,value,hdrsi,rmd160,j,type,fileid,(uint32_t)scriptpos,scriptlen,ramchain->H.txidind-rdata->firsti) == 0 )
                            return(-3);
                    }
                }
                else
                {
                    hdrsi = rdata->hdrsi;
                    value = U[ramchain->H.unspentind].value;
                    memcpy(rmd160,U[ramchain->H.unspentind].rmd160,20);
                    type = U[ramchain->H.unspentind].type & 0xf;
                    fileid = U[ramchain->H.unspentind].fileid;
                    scriptpos = U[ramchain->H.unspentind].scriptpos;
                    scriptlen = U[ramchain->H.unspentind].scriptlen;
                    //printf("scriptpos.%u scriptlen.%d type.%d %.8f\n",(uint32_t)scriptpos,scriptlen,type,dstr(value));
                    /*if ( U[ramchain->H.unspentind].scriptoffset != 0 )
                    {
                        scriptdata = &Kspace[U[ramchain->H.unspentind].scriptoffset];
                        scriptlen = U[ramchain->H.unspentind].scriptlen;
                    }
                    if ( 0 && scriptdata != 0 && scriptlen > 0 )
                    {
                        int32_t i; for (i=0; i<scriptlen; i++)
                            printf("%02x",scriptdata[i]);
                        fprintf(stderr," raw unspent script type.%d U%d offset.%d\n",type,ramchain->H.unspentind,U[ramchain->H.unspentind].scriptoffset);
                    } //else printf("no script\n");*/
                    if ( iguana_ramchain_addunspent20(coin,0,RAMCHAIN_ARG,value,0,scriptlen,tx->txid,j,type,bp,rmd160) == 0 )
                        return(-4);
                    if ( 0 )
                    {
                        int32_t i; for (i=0; i<20; i++)
                            printf("%02x",rmd160[i]);
                        char str[65]; printf(" raw rmd160 txid.(%s) txidind.%u j.%d\n",bits256_str(str,tx->txid),ramchain->H.txidind,j);
                    }
                }
                if ( dest != 0 )
                {
                    if ( iguana_ramchain_addunspent(coin,RAMCHAIN_DESTARG,value,hdrsi,rmd160,j,type,fileid,(uint32_t)scriptpos,scriptlen,ramchain->H.txidind-rdata->firsti) == 0 )
                        return(-5);
                } //else printf("addunspent20 done\n");
            } else return(-6);
        }
        ramchain->H.spendind += tx->numvins;
        if ( dest != 0 )
        {
            dest->H.txidind++;
            dest->H.spendind += tx->numvins;
        } //else printf("iter scriptoffset.%u/%u stacksize.%u/%u\n",ramchain->H.scriptoffset,ramchain->H.data->scriptspace,ramchain->H.stacksize,ramchain->H.data->stackspace);
    }
    if ( dest != 0 )
    {
        dest->H.txidind = desttxidind;
        dest->H.spendind = destspendind;
    } //else printf("Start VINs\n");
    ramchain->H.txidind = ramchain->H.spendind = rdata->firsti;
    for (ramchain->H.txidind=rdata->firsti; ramchain->H.txidind<rdata->numtxids; ramchain->H.txidind++)
    {
        tx = &T[ramchain->H.txidind];
        for (j=0; j<tx->numvins; j++)
        {
            if ( coin->active == 0 )
                return(-1);
            fileid = 0;
            scriptpos = 0;
            scriptlen = 0;
            if ( ramchain->expanded != 0 )
            {
                fileid = Sx[ramchain->H.spendind].fileid;
                scriptpos = Sx[ramchain->H.spendind].scriptpos;
                scriptlen = Sx[ramchain->H.spendind].scriptlen;
          //scriptlen = iguana_vinscriptdecode(coin,ramchain,&metalen,_script,&Kspace[ramchain->H.data->scriptspace],Kspace,&Sx[ramchain->H.spendind]);
                //scriptdata = _script;
                prevout = iguana_ramchain_txid(coin,RAMCHAIN_ARG,&prevhash,&Sx[ramchain->H.spendind]);
                //fprintf(stderr,"from expanded iter\n");
                if ( iguana_ramchain_addspend(coin,RAMCHAIN_ARG,prevhash,prevout,Sx[ramchain->H.spendind].sequenceid,bp->hdrsi,fileid,scriptpos,scriptlen) == 0 )
                {
                    char str[65];
                    printf("hdrsi.%d txidind.%d spendind.%d spendtxid.%x %d vin.%d %s vout.%d\n",bp->bundleheight,ramchain->H.txidind,ramchain->H.spendind,Sx[ramchain->H.spendind].spendtxidind,Sx[ramchain->H.spendind].spendtxidind&0xfffffff,j,bits256_str(str,prevhash),prevout);
                    //for (i=0; i<ramchain->H.data->numexternaltxids; i++)
                    //    printf("%p X[%d] %s\n",X,i,bits256_str(str,X[i]));
                    //exit(-1);
                    iguana_ramchain_txid(coin,RAMCHAIN_ARG,&prevhash,&Sx[ramchain->H.spendind]);
                    return(-7);
                }
            }
            else
            {
                //spendind = (tx->firstvin + j);
                sequenceid = S[ramchain->H.spendind].sequenceid;
                prevhash = S[ramchain->H.spendind].prevhash2;
                prevout = S[ramchain->H.spendind].prevout;
                fileid = S[ramchain->H.spendind].fileid;
                scriptpos = S[ramchain->H.spendind].scriptpos;
                scriptlen = S[ramchain->H.spendind].vinscriptlen;
                /*if ( S[ramchain->H.spendind].scriptoffset != 0 )
                {
                    scriptdata = &Kspace[S[ramchain->H.spendind].scriptoffset];
                    scriptlen = S[ramchain->H.spendind].vinscriptlen;
                }*/
                /*if ( scriptdata != 0 && scriptlen > 0 )
                {
                    int32_t i; for (i=0; i<scriptlen; i++)
                        printf("%02x",scriptdata[i]);
                    printf(" spendind.%d vinscript\n",ramchain->H.spendind);
                }*/
                if ( iguana_ramchain_addspend256(coin,0,RAMCHAIN_ARG,prevhash,prevout,0,scriptlen,sequenceid,bp) == 0 )
                    return(-8);
            }
            if ( dest != 0 )
            {
                if ( iguana_ramchain_addspend(coin,RAMCHAIN_DESTARG,prevhash,prevout,sequenceid,bp->hdrsi,fileid,scriptpos,scriptlen) == 0 )
                    return(-9);
                //printf("from dest iter scriptspace.%d\n",dest->H.stacksize);
            }
        }
        if ( dest != 0 )
            dest->H.txidind++;
    }
    return(0);
}

long iguana_ramchain_data(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_txblock *origtxdata,struct iguana_msgtx *txarray,int32_t txn_count,uint8_t *data,int32_t recvlen)
{
    static uint64_t totalrecv;
    int32_t verifyflag = 0;
    RAMCHAIN_DECLARE; uint32_t addr_ipbits; struct iguana_ramchain R,*mapchain,*ramchain = &addr->ramchain;
    struct iguana_msgtx *tx; char fname[1024]; uint8_t rmd160[20]; // long fsize; void *ptr;
    int32_t i,j,fpos,pubkeysize,msize,sigsize,subdir,firsti=1,err,flag,bundlei = -2; bits256 merkle_root;
    struct iguana_bundle *bp = 0; struct iguana_block *block; uint32_t scriptspace,stackspace;
    totalrecv += recvlen;
#ifdef __PNACL__
    //verifyflag = 1;
#endif
    if ( (addr_ipbits= (uint32_t)addr->ipbits) == 0 )
        addr_ipbits = 1;
    if ( bits256_nonz(origtxdata->zblock.RO.merkle_root) == 0 )
    {
        memset(&origtxdata->zblock.RO.prev_block,0,sizeof(bits256));
        origtxdata->zblock.RO.recvlen = 0;
        origtxdata->zblock.issued = 0;
        return(-1);
    }
    for (i=0; i<sizeof(addr->dirty)/sizeof(*addr->dirty); i++)
        addr->dirty[i] = 0;
    msize = (int32_t)sizeof(bits256) * (txn_count+1) * 2;
    if ( msize <= addr->TXDATA.totalsize )
    {
        bits256 *tree = addr->TXDATA.ptr;
        iguana_memreset(&addr->TXDATA);
        for (i=0; i<txn_count; i++)
            tree[i] = txarray[i].txid;
        merkle_root = iguana_merkle(tree,txn_count);
        if ( bits256_cmp(merkle_root,origtxdata->zblock.RO.merkle_root) != 0 )
        {
            char str[65],str2[65];
            printf(">>>>>>>>>> merkle mismatch.[%d] calc.(%s) vs (%s)\n",txn_count,bits256_str(str,merkle_root),bits256_str(str2,origtxdata->zblock.RO.merkle_root));
            origtxdata->zblock.RO.recvlen = 0;
            origtxdata->zblock.issued = 0;
            return(-1);
        } //else printf("matched merkle.%d\n",txn_count);
    } else printf("not enough memory for merkle verify %d vs %lu\n",(int32_t)(sizeof(bits256)*(txn_count+1)),(long)addr->TXDATA.totalsize);
    bp = 0, bundlei = -2;
    if ( iguana_bundlefind(coin,&bp,&bundlei,origtxdata->zblock.RO.hash2) == 0 )
    {
        bp = 0, bundlei = -2;
        if ( iguana_bundlefind(coin,&bp,&bundlei,origtxdata->zblock.RO.prev_block) == 0 )
        {
            origtxdata->zblock.RO.recvlen = 0;
            origtxdata->zblock.issued = 0;
            return(-1);
        }
        else if ( bundlei < coin->chain->bundlesize-1 )
            bundlei++;
        else
        {
            origtxdata->zblock.issued = 0;
            origtxdata->zblock.RO.recvlen = 0;
            char str[65]; printf("ramchain data: error finding block %s\n",bits256_str(str,origtxdata->zblock.RO.hash2));
            return(-1);
        }
    }
    if ( (block= bp->blocks[bundlei]) == 0 || bits256_cmp(block->RO.hash2,origtxdata->zblock.RO.hash2) != 0 || bits256_cmp(bp->hashes[bundlei],origtxdata->zblock.RO.hash2) != 0 )
    {
        char str[65];
        if ( 0 && block != 0 )
            printf("%d:%d has no block ptr.%p %s or wrong hash\n",bp->hdrsi,bundlei,block,bits256_str(str,origtxdata->zblock.RO.hash2));
        return(-1);
    }
    block->txvalid = 1;
    if ( block->fpipbits != 0 && block->fpos >= 0 )
    {
        static int32_t numredundant; static double redundantsize; static uint32_t lastdisp;
        char str[65],str2[65];
        numredundant++, redundantsize += recvlen;
        if ( time(NULL) > lastdisp+30 )
        {
            lastdisp = (uint32_t)time(NULL);
            printf("ramchaindata have %d:%d at %d | %d blocks %s redundant xfers total %s %.2f%% wasted\n",bp->hdrsi,bundlei,block->fpos,numredundant,mbstr(str,redundantsize),mbstr(str2,totalrecv),100.*redundantsize/totalrecv);
        }
        return(block->fpos);
    }
    sigsize = pubkeysize = 0;
    scriptspace = 1;//iguana_scriptspaceraw(coin,&scriptsize,&sigsize,&pubkeysize,txarray,txn_count);
    if ( iguana_ramchain_init(fname,ramchain,&addr->TXDATA,&addr->HASHMEM,1,txn_count,origtxdata->numunspents,origtxdata->numspends,0,0,(scriptspace+sigsize+pubkeysize)*1.1,0,1,coin->chain->zcash) == 0 )
    {
        if ( block->fpipbits == 0 )
            block->issued = block->RO.recvlen = 0, block->fpos = -1;
        return(-1);
    }
    block->fpos = fpos = -1;
    iguana_ramchain_link(ramchain,block->RO.hash2,bp->hdrsi,bp->bundleheight+bundlei,bundlei,1,firsti,0);
    _iguana_ramchain_setptrs(RAMCHAIN_PTRS,ramchain->H.data);
    subdir = bp->bundleheight / IGUANA_SUBDIRDIVISOR;
    char dirname[1024]; sprintf(dirname,"%s/%s/%d",GLOBAL_TMPDIR,coin->symbol,subdir), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/%s/%d/%d",GLOBAL_TMPDIR,coin->symbol,subdir,bp->bundleheight), OS_ensure_directory(dirname);
    //printf("Kspace.%p bp.[%d:%d] <- scriptspace.%d expanded.%d\n",Kspace,bp->hdrsi,bundlei,scriptspace,ramchain->expanded);
    if ( T == 0 || U == 0 || S == 0 || B == 0 )
    {
        block->issued = 0;
        block->RO.recvlen = 0;
        printf("fatal error getting txdataptrs %p %p %p %p\n",T,U,S,B);
        return(-1);
    }
    block->fpipbits = 1;
    for (i=0; i<txn_count; i++,ramchain->H.txidind++)
    {
        tx = &txarray[i];
        iguana_ramchain_addtxid(coin,RAMCHAIN_ARG,tx->txid,tx->tx_out,tx->tx_in,tx->lock_time,tx->version,tx->timestamp,bundlei);
        for (j=0; j<tx->tx_out; j++)
        {
            memset(rmd160,0,sizeof(rmd160));
            //printf("i.%d j.%d pkscriptlen.%d\n",i,j,tx->vouts[j].pk_scriptlen);
            iguana_ramchain_addunspent20(coin,addr,RAMCHAIN_ARG,tx->vouts[j].value,tx->vouts[j].pk_script,tx->vouts[j].pk_scriptlen,tx->txid,j,-1,bp,rmd160);
        }
        ramchain->H.spendind += tx->tx_in;
    }
    //printf("scriptoffset.%d after %d txids\n",ramchain->H.scriptoffset,txn_count);
    ramchain->H.txidind = ramchain->H.spendind = ramchain->H.data->firsti;
    for (i=0; i<txn_count; i++,ramchain->H.txidind++)
    {
        tx = &txarray[i];
        for (j=0; j<tx->tx_in; j++)
        {
             iguana_ramchain_addspend256(coin,addr,RAMCHAIN_ARG,tx->vins[j].prev_hash,tx->vins[j].prev_vout,tx->vins[j].vinscript,tx->vins[j].scriptlen,tx->vins[j].sequence,bp);//,bp->hdrsi,bundlei);
        }
    }
    ramchain->H.data->prevhash2 = block->RO.prev_block;
    ramchain->H.data->scriptspace = scriptspace = ramchain->H.scriptoffset;
    ramchain->H.data->stackspace = stackspace = ramchain->H.stacksize;
    iguana_ramchain_setsize(fname,ramchain,ramchain->H.data,1,coin->chain->zcash);
    flag = 0;
    if ( ramchain->H.txidind != ramchain->H.data->numtxids || ramchain->H.unspentind != ramchain->H.data->numunspents || ramchain->H.spendind != ramchain->H.data->numspends )
    {
        printf("error creating PT ramchain.[%d:%d] ramchain->txidind %d != %d ramchain->data->numtxids || ramchain->unspentind %d != %d ramchain->data->numunspents || ramchain->spendind %d != %d ramchain->data->numspends space.(%d v %d)\n",bp->hdrsi,bp->bundleheight,ramchain->H.txidind,ramchain->H.data->numtxids,ramchain->H.unspentind,ramchain->H.data->numunspents,ramchain->H.spendind,ramchain->H.data->numspends,ramchain->H.scriptoffset,ramchain->H.data->scriptspace);
        block->fpipbits = 0;
        block->issued = 0;
        block->RO.recvlen = 0;
    }
    else
    {
        if ( (err= iguana_ramchain_verify(coin,ramchain)) == 0 )
        {
            int32_t bROsize = (int32_t)(sizeof(struct iguana_blockRO) + coin->chain->zcash*sizeof(struct iguana_msgblockhdr_zcash));
            memcpy(B,&block->RO,bROsize);
            ramchain->H.data->scriptspace = ramchain->H.scriptoffset = scriptspace;
            ramchain->H.data->stackspace = ramchain->H.stacksize = stackspace;
            if ( (fpos= (int32_t)iguana_ramchain_save(coin,RAMCHAIN_ARG,addr_ipbits,block->RO.hash2,block->RO.prev_block,bundlei,0,coin->chain->zcash)) >= 0 )
            {
                origtxdata->datalen = (int32_t)ramchain->H.data->allocsize;
                //char str[65]; printf("saved.%s [%d:%d] fpos.%d datalen.%d\n",bits256_str(str,block->RO.hash2),bp->hdrsi,bundlei,fpos,origtxdata->datalen);
                ramchain->H.ROflag = 0;
                flag = 1;
                if ( addr->dirty[0] != 0 && addr->voutsfp != 0 )
                    fflush(addr->voutsfp);
                if ( addr->dirty[1] != 0 && addr->vinsfp != 0 )
                    fflush(addr->vinsfp);
                memset(&R,0,sizeof(R));
                if ( verifyflag != 0 && (mapchain= iguana_ramchain_map(coin,fname,0,1,&R,0,addr_ipbits,block->RO.hash2,block->RO.prev_block,bundlei,fpos,1,0)) == 0 )
                {
                    printf("delete unverified [%d:%d]\n",bp->hdrsi,bundlei);
                    iguana_ramchain_free(coin,&R,1);
                    fpos = -1;
                    //printf("mapped Soffset.%ld\n",(long)mapchain->data->Soffset);
                    /*iguana_ramchain_link(&R,block->RO.hash2,bp->hdrsi,bp->bundleheight+bundlei,bundlei,1,firsti,1);
                    if ( 1 ) // unix issues?
                    {
                        if ( (err= iguana_ramchain_cmp(ramchain,mapchain,0)) != 0 )
                            fpos = -1, printf("error.%d comparing ramchains\n",err);
                        else
                        {
                            ptr = mapchain->fileptr; fsize = mapchain->filesize;
                            mapchain->fileptr = 0, mapchain->filesize = 0;
                            iguana_ramchain_free(coin,mapchain,1);
                            memset(&R,0,sizeof(R));
                            R.H.data = (void *)(long)((long)ptr + fpos), R.filesize = fsize;
                            iguana_ramchain_link(&R,block->RO.hash2,bp->hdrsi,bp->bundleheight+bundlei,bundlei,1,firsti,1);
                        }
                    }
                    if ( (err= iguana_ramchain_cmp(ramchain,&R,0)) != 0 )
                    {
                        fpos = -1;
                        block->issued = 0;
                        block->RO.recvlen = 0;
                        printf("error.%d comparing REMAP ramchains\n",err);
                    }
                    else
                    {
                        iguana_ramchain_extras(coin,&R,0,0);
                        if ( (err= iguana_ramchain_iterate(coin,0,&R,bp,bundlei)) != 0 )
                            printf("err.%d iterate ",err);
                        //printf("SUCCESS REMAP\n");
                        bp->numtxids += ramchain->H.data->numtxids;
                        bp->numunspents += ramchain->H.data->numunspents;
                        bp->numspends += ramchain->H.data->numspends;
                        //bp->rawscriptspace += ramchain->H.data->scriptspace;
                    }
                    iguana_ramchain_free(coin,&R,1);
                    if ( err != 0 )
                        iguana_blockunmark(coin,block,bp,bundlei,1);*/
                }
                else
                {
                    bp->numtxids += ramchain->H.data->numtxids;
                    bp->numunspents += ramchain->H.data->numunspents;
                    bp->numspends += ramchain->H.data->numspends;
                    //bp->rawscriptspace += ramchain->H.data->scriptspace;
                }
                if ( fpos >= 0 )
                    block->fpos = fpos, block->fpipbits = addr_ipbits;
            } else printf("save error\n");
        }
        else
        {
            printf("ramchain verification error.%d hdrsi.%d bundlei.%d n.%d\n",err,bp->hdrsi,bundlei,bp->n);
            fpos = -1;
        }
    }
    if ( fpos < 0 )
        iguana_blockunmark(coin,block,bp,bundlei,1);
    //fprintf(stderr,"finished with hdrsi.%d ht.%d scripts.%u:%u\n",bp->hdrsi,bp->bundleheight,ramchain->H.scriptoffset,ramchain->H.data->scriptspace);
    ramchain->H.ROflag = 0;
    iguana_ramchain_free(coin,ramchain,0);
    return(fpos);
}

// two passes to check data size

void iguana_ramchain_disp(struct iguana_ramchain *ramchain)
{
    RAMCHAIN_DECLARE; int32_t j; uint32_t txidind,unspentind,spendind; struct iguana_txid *tx; char str[65];
    _iguana_ramchain_setptrs(RAMCHAIN_PTRS,ramchain->H.data);
    if ( ramchain->H.data != 0 )
    {
        unspentind = spendind = ramchain->H.data->firsti;
        for (txidind=ramchain->H.data->firsti; txidind<ramchain->H.data->numtxids; txidind++)
        {
            tx = &T[txidind];
            for (j=0; j<tx->numvins; j++, spendind++)
                printf("%s/v%d ",bits256_str(str,S[spendind].prevhash2),S[spendind].prevout);
            for (j=0; j<tx->numvouts; j++,unspentind++)
            {
                init_hexbytes_noT(str,U[unspentind].rmd160,20);
                printf("(%.8f %s) ",dstr(U[unspentind].value),str);
            }
            printf("txid.[%d] %s (%d:%d %d:%d)\n",txidind,bits256_str(str,tx->txid),tx->firstvout,tx->numvouts,tx->firstvin,tx->numvins);
        }
    }
}

void iguana_blockunmark(struct iguana_info *coin,struct iguana_block *block,struct iguana_bundle *bp,int32_t i,int32_t deletefile)
{
    void *ptr; int32_t recvlen,hdrsi,checki; char fname[1024]; static const bits256 zero;
    if ( 0 && bp != 0 )
        printf("UNMARK.[%d:%d]\n",bp->hdrsi,i);
    if ( block != 0 )
    {
        block->queued = 0;
        block->fpipbits = 0;
        block->fpos = -1;
        block->txvalid = 0;
        block->issued = 0;
    }
    if ( bp != 0 && i >= 0 && i < bp->n )
    {
        bp->issued[i] = 0;
        if ( (ptr= bp->speculativecache[i]) != 0 )
        {
            memcpy(&recvlen,ptr,sizeof(recvlen));
            free(ptr);
            bp->speculativecache[i] = 0;
        }
    }
    if ( deletefile != 0 )
    {
        fname[0] = 0;
        if ( block != 0 && (checki= iguana_peerfname(coin,&hdrsi,GLOBAL_TMPDIR,fname,0,block->RO.hash2,zero,1,1)) != i )
        {
            //printf("checki.%d vs %d mismatch? %s\n",checki,i,fname);
        }
        if ( fname[0] != 0 )
            OS_removefile(fname,0);
    }
}

int32_t iguana_oldbundlefiles(struct iguana_info *coin,uint32_t *ipbits,void **ptrs,long *filesizes,struct iguana_bundle *bp)
{
    static const bits256 zero;
    int32_t j,bundlei,num,hdrsi,checki; struct iguana_block *block; uint32_t fpipbits; char fname[1024];
    for (bundlei=num=0; bundlei<bp->n; bundlei++)
    {
        if ( (block= bp->blocks[bundlei]) != 0 )
            fpipbits = block->fpipbits;
        else
        {
            iguana_blockunmark(coin,block,bp,bundlei,0);
            return(0);
        }
        if ( num > 0 )
        {
            for (j=0; j<num; j++)
                if ( ipbits[j] == fpipbits )
                    break;
        } else j = 0;
        if ( j == num )
        {
            ipbits[num] = fpipbits;
            if ( (checki= iguana_peerfname(coin,&hdrsi,GLOBAL_TMPDIR,fname,fpipbits,bp->hashes[bundlei],zero,1,1)) != bundlei || bundlei < 0 || bundlei >= coin->chain->bundlesize )
            {
                printf("B iguana_ramchain_map.(%s) illegal hdrsi.%d bundlei.%d checki.%d\n",fname,hdrsi,bundlei,checki);
                return(0);
            }
            if ( (ptrs[num]= OS_mapfile(fname,&filesizes[num],0)) == 0 )
            {
                printf("error mapping bundlei.%d (%s)\n",bundlei,fname);
                iguana_blockunmark(coin,block,bp,bundlei,1);
                return(0);
            }
            //printf("%s mapped ptrs[%d] filesize.%ld bundlei.%d ipbits.%x fpos.%d\n",fname,num,(long)filesizes[num],bundlei,fpipbits,bp->fpos[bundlei]);
            num++;
        }
    }
    return(num);
}

void *iguana_bundlefile(struct iguana_info *coin,char *fname,long *filesizep,struct iguana_bundle *bp,int32_t bundlei)
{
    int32_t checki,hdrsi; void *ptr = 0; FILE *fp; static const bits256 zero;
    *filesizep = 0;
    fname[0] = 0;
    if ( (checki= iguana_peerfname(coin,&hdrsi,GLOBAL_TMPDIR,fname,0,bp->hashes[bundlei],zero,1,1)) != bundlei || bundlei < 0 || bundlei >= coin->chain->bundlesize )
    {
        printf("B iguana_ramchain_map.(%s) illegal hdrsi.%d bundlei.%d checki.%d\n",fname,hdrsi,bundlei,checki);
        return(0);
    }
    if ( (fp= fopen(fname,"rb")) == 0 )
        return(0);
    else
    {
        fclose(fp);
        if ( (ptr= OS_mapfile(fname,filesizep,0)) == 0 )
        {
            printf("error mapping.(%s) bundlei.%d\n",fname,bundlei);
            return(0);
        }
    }
    //printf("mapped.(%s) bundlei.[%d:%d] %p[%ld]\n",fname,hdrsi,bundlei,ptr,*filesizep);
    return(ptr);
}

int32_t iguana_bundlefiles(struct iguana_info *coin,uint32_t *ipbits,void **ptrs,long *filesizes,struct iguana_bundle *bp,int32_t starti,int32_t endi)
{
    int32_t bundlei,num = 0; char fname[1024];
    for (bundlei=starti; bundlei<=endi; bundlei++)
    {
        if ( (ptrs[num]= iguana_bundlefile(coin,fname,&filesizes[num],bp,bundlei)) != 0 )
            num++;
        else
        {
            printf("%s error ptrs[%d] filesize.%ld bundlei.%d ipbits.%x\n",fname,num,(long)filesizes[num],bundlei,ipbits[bundlei]);
            return(bp == coin->current ? num : 0);
        }
    }
    return(num);
}

void iguana_bundlemapfree(struct iguana_info *coin,struct OS_memspace *mem,struct OS_memspace *hashmem,uint32_t *ipbits,void **ptrs,long *filesizes,int32_t num,struct iguana_ramchain *R,int32_t starti,int32_t endi)
{
    int32_t j,n = (endi - starti + 1);
    for (j=0; j<num; j++)
        if ( ptrs[j] != 0 && filesizes[j] != 0 )
        {
            //printf("unmap.%d/%d: %p %ld\n",j,num,ptrs[j],filesizes[j]);
            munmap(ptrs[j],filesizes[j]);
        }
    myfree(ptrs,n * sizeof(*ptrs));
    myfree(ipbits,n * sizeof(*ipbits));
    myfree(filesizes,n * sizeof(*filesizes));
    if ( R != 0 )
    {
        for (j=starti; j<=endi; j++)
        {
            //printf("R[%d]\n",j);
            R[j].fileptr = 0;
            R[j].filesize = 0;
            iguana_ramchain_free(coin,&R[j],1);
        }
        myfree(R,n * sizeof(*R));
    }
    if ( mem != 0 )
        iguana_mempurge(mem);
    if ( hashmem != 0 )
        iguana_mempurge(hashmem);
}

int32_t iguana_ramchain_expandedsave(struct iguana_info *coin,RAMCHAIN_FUNC,struct iguana_ramchain *newchain,struct OS_memspace *hashmem,int32_t cmpflag,struct iguana_bundle *bp)
{
    static const bits256 zero;
    bits256 firsthash2; int32_t err,bundlei,hdrsi,numblocks,firsti,height,retval= -1;
    struct iguana_ramchain checkR,*mapchain; char fname[1024]; struct iguana_block *block;
    uint32_t scriptspace,scriptoffset,stacksize; uint8_t *destoffset,*srcoffset;
    firsthash2 = ramchain->H.data->firsthash2;//, lasthash2 = ramchain->H.data->lasthash2;
    height = ramchain->height, firsti = ramchain->H.data->firsti, hdrsi = ramchain->H.hdrsi, numblocks = ramchain->numblocks;
    destoffset = &Kspace[ramchain->H.scriptoffset];
    srcoffset = &Kspace[ramchain->H.data->scriptspace - ramchain->H.stacksize];
    if ( ramchain->expanded != 0 )
    {
        if ( (long)destoffset > (long)srcoffset )
            printf("smashed stack? dest.%ld vs src %ld offset.%u stacksize.%u space.%u\n",(long)destoffset,(long)srcoffset,(uint32_t)ramchain->H.scriptoffset,(uint32_t)ramchain->H.stacksize,(uint32_t)ramchain->H.scriptoffset);
    }
    //printf("%d SAVE: Koffset.%d scriptoffset.%d stacksize.%d allocsize.%d gap.%ld RO.%d\n",bp->bundleheight,(int32_t)ramchain->H.data->Koffset,ramchain->H.scriptoffset,ramchain->H.stacksize,(int32_t)ramchain->H.data->allocsize,(long)destoffset - (long)srcoffset,ramchain->H.ROflag);
    scriptspace = ramchain->H.data->scriptspace;
    scriptoffset = ramchain->H.scriptoffset;
    stacksize = ramchain->H.stacksize;
    //ramchain->H.scriptoffset = scriptoffset;
    if ( (block= bp->blocks[0]) != 0 )
        ramchain->H.data->prevhash2 = block->RO.prev_block;
    ramchain->H.data->scriptspace = scriptoffset;
    ramchain->H.stacksize = ramchain->H.data->stackspace = stacksize;
    iguana_ramchain_setsize(fname,ramchain,ramchain->H.data,bp->n,coin->chain->zcash);
    //printf("Apresave T.%d U.%d S.%d P.%d X.%d -> size.%ld firsti.%d scriptoffset.%d stacksize.%d\n",ramchain->H.data->numtxids,ramchain->H.data->numunspents,ramchain->H.data->numspends,ramchain->H.data->numpkinds,ramchain->H.data->numexternaltxids,(long)ramchain->H.data->allocsize,firsti,ramchain->H.scriptoffset,ramchain->H.stacksize);
    *newchain = *ramchain;
    //memcpy(ramchain->roU2,ramchain->U2,sizeof(*ramchain->U2) * ramchain->H.data->numunspents);
    //memcpy(ramchain->roP2,ramchain->P2,sizeof(*ramchain->P2) * ramchain->H.data->numpkinds);
    memcpy(ramchain->creditsA,ramchain->A,sizeof(*ramchain->A) * ramchain->H.data->numpkinds);
    memset(ramchain->A,0,sizeof(*ramchain->A) * ramchain->H.data->numpkinds);
    //printf("presave T.%d U.%d S.%d P.%d X.%d -> size.%ld firsti.%d\n",ramchain->H.data->numtxids,ramchain->H.data->numunspents,ramchain->H.data->numspends,ramchain->H.data->numpkinds,ramchain->H.data->numexternaltxids,(long)ramchain->H.data->allocsize,firsti);
    //printf("0 preSAVE: Koffset.%d scriptoffset.%d stacksize.%d allocsize.%d\n",(int32_t)ramchain->H.data->Koffset,ramchain->H.scriptoffset,ramchain->H.stacksize,(int32_t)ramchain->H.data->allocsize);
    if ( (err= iguana_ramchain_iterate(coin,0,ramchain,bp,-1)) != 0 )
        printf("ERROR.%d iterating presave ramchain hdrsi.%d\n",err,hdrsi);
    else
    {
        //printf("postiterate0.%d T.%d U.%d S.%d P.%d X.%d -> size.%ld firsti.%d scripts.%d:%d stack.%d:%d\n",bp->bundleheight,ramchain->H.data->numtxids,ramchain->H.data->numunspents,ramchain->H.data->numspends,ramchain->H.data->numpkinds,ramchain->H.data->numexternaltxids,(long)ramchain->H.data->allocsize,firsti,(int32_t)ramchain->H.scriptoffset,scriptoffset,(int32_t)ramchain->H.stacksize,stacksize);
        if ( ramchain->H.scriptoffset > scriptoffset || ramchain->H.stacksize > stacksize )
            printf("MEMORY OVERFLOW\n");
        if ( (err= iguana_ramchain_verify(coin,ramchain)) != 0 )
            printf("ERROR.%d verifying presave ramchain hdrsi.%d\n",err,hdrsi);
        else retval = 0;
    }
    //printf("postiterateA.%d T.%d U.%d S.%d P.%d X.%d -> size.%ld firsti.%d scripts.%d:%d stack.%d:%d\n",bp->bundleheight,ramchain->H.data->numtxids,ramchain->H.data->numunspents,ramchain->H.data->numspends,ramchain->H.data->numpkinds,ramchain->H.data->numexternaltxids,(long)ramchain->H.data->allocsize,firsti,(int32_t)ramchain->H.scriptoffset,scriptoffset,(int32_t)ramchain->H.stacksize,stacksize);
    ramchain->H.scriptoffset = scriptoffset;
    ramchain->H.data->scriptspace = scriptoffset;
    ramchain->H.stacksize = ramchain->H.data->stackspace = stacksize;
    if ( iguana_ramchain_save(coin,RAMCHAIN_ARG,0,firsthash2,zero,0,bp,coin->chain->zcash) < 0 )
    {
        printf("ERROR saving ramchain hdrsi.%d, deleting and will regenerate\n",hdrsi);
        iguana_mempurge(hashmem);
    }
    else
    {
        //printf("DEST T.%d U.%d S.%d P.%d X.%d -> size.%ld Xoffset.%d\n",ramchain->H.data->numtxids,ramchain->H.data->numunspents,ramchain->H.data->numspends,ramchain->H.data->numpkinds,ramchain->H.data->numexternaltxids,(long)ramchain->H.data->allocsize,(int32_t)ramchain->H.data->Xoffset);
        //printf("free dest hdrs.%d retval.%d\n",bp->hdrsi,retval);
        memset(&checkR,0,sizeof(checkR));
        checkR.sigsfileptr = ramchain->sigsfileptr;
        checkR.sigsfilesize = ramchain->sigsfilesize;
        bundlei = 0;
        if ( cmpflag == 0 )
            iguana_memreset(hashmem);
        if ( (mapchain= iguana_ramchain_map(coin,fname,bp,numblocks,&checkR,cmpflag==0?hashmem:0,0,firsthash2,zero,bundlei,0,0,1)) != 0 )
        {
            iguana_ramchain_link(mapchain,firsthash2,hdrsi,height,0,numblocks,firsti,1);
            iguana_ramchain_extras(coin,mapchain,hashmem,0);
            //printf("expSAVE: Koffset.%d scriptoffset.%d stacksize.%d allocsize.%d\n",(int32_t)mapchain->H.data->Koffset,mapchain->H.scriptoffset,mapchain->H.stacksize,(int32_t)mapchain->H.data->allocsize);
            if ( (err= iguana_ramchain_iterate(coin,0,mapchain,bp,bundlei)) != 0 )
                printf("err.%d iterate mapped dest\n",err);
            else if ( cmpflag != 0 )
            {
                if ( (err= iguana_ramchain_cmp(mapchain,ramchain,0)) != 0 )
                    printf("err.%d cmp mapchain.%d vs ramchain\n",err,height);
                else
                {
                    printf("BUNDLE.%d iterated and compared\n",height);
                    retval = 0;
                }
            }
            //printf("%08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %llx ht.%d bundlehashes.%s\n",mapchain->H.data->lhashes[0].uints[0],mapchain->H.data->lhashes[1].uints[0],mapchain->H.data->lhashes[2].uints[0],mapchain->H.data->lhashes[3].uints[0],mapchain->H.data->lhashes[4].uints[0],mapchain->H.data->lhashes[5].uints[0],mapchain->H.data->lhashes[6].uints[0],mapchain->H.data->lhashes[7].uints[0],mapchain->H.data->lhashes[8].uints[0],mapchain->H.data->lhashes[9].uints[0],(long long)mapchain->H.data->sha256.txid,mapchain->height,coin->symbol);
            iguana_ramchain_free(coin,mapchain,cmpflag);
        }
        iguana_mempurge(hashmem);
    }
    if ( retval < 0 )
    {
        printf("remove unmappable bundle.[%d]\n",bp->hdrsi);
        iguana_bundleremove(coin,bp->hdrsi,0);
    }
    return(retval);
}

struct iguana_ramchain *iguana_bundleload(struct iguana_info *coin,struct iguana_ramchain *ramchain,struct iguana_bundle *bp,int32_t extraflag)
{
    static const bits256 zero;
    struct iguana_blockRO *B; struct iguana_txid *T; int32_t i,bROsize,firsti = 1; char fname[512];
    struct iguana_block *block,*prev,*prev2; struct iguana_ramchain *mapchain;
    memset(ramchain,0,sizeof(*ramchain));
    bROsize = (int32_t)(sizeof(struct iguana_blockRO) + coin->chain->zcash*sizeof(struct iguana_msgblockhdr_zcash));
    if ( (mapchain= iguana_ramchain_map(coin,fname,bp,bp->n,ramchain,0,0,bp->hashes[0],zero,0,0,extraflag,1)) != 0 )
    {
        iguana_ramchain_link(mapchain,bp->hashes[0],bp->hdrsi,bp->bundleheight,0,bp->n,firsti,1);
        //char str[65]; printf("bp.%d: T.%d U.%d S.%d P%d X.%d MAPPED %s %p\n",bp->hdrsi,mapchain->H.data->numtxids,mapchain->H.data->numunspents,mapchain->H.data->numspends,mapchain->H.data->numpkinds,mapchain->H.data->numexternaltxids,mbstr(str,mapchain->H.data->allocsize),mapchain->H.data);
        //ramcoder_test(mapchain->H.data,mapchain->H.data->allocsize);
        B = RAMCHAIN_PTR(ramchain->H.data,Boffset);
        T = RAMCHAIN_PTR(ramchain->H.data,Toffset);
        prev = prev2 = 0;
        for (i=0; i<bp->n; i++)
        {
            if ( (block= bp->blocks[i]) != 0 || (block= iguana_blockhashset("bundleload",coin,bp->bundleheight+i,bp->hashes[i],1)) != 0 )
            {
                if ( bits256_to_compact(bits256_from_compact(block->RO.bits)) != block->RO.bits )
                {
                    char str[65];
                    printf("nbits calc error %x -> %s -> %x\n",block->RO.bits,bits256_str(str,bits256_from_compact(block->RO.bits)),bits256_to_compact(bits256_from_compact(block->RO.bits)));
                }
                block->queued = 1;
                block->txvalid = 1;
                block->height = bp->bundleheight + i;
                block->hdrsi = bp->hdrsi;
                block->bundlei = i;
                block->fpipbits = (uint32_t)calc_ipbits("127.0.0.1");
                memcpy(&block->RO,(void *)((long)B + i*bROsize),bROsize);
                //printf("%x ",(int32_t)B[i].hash2.ulongs[3]);
                iguana_hash2set(coin,"bundleload",bp,i,block->RO.hash2);
                bp->blocks[i] = block;
                //if ( bits256_nonz(bp->hashes[i]) == 0 )
                //    bp->hashes[i] = bRO->hash2;
                if ( (prev= block->hh.prev) != 0 )
                    prev2 = prev->hh.prev;
                if ( prev2 != 0 && prev != 0 && strcmp(coin->symbol,"BTCD") == 0 && bp->bundleheight > 20000 && prev != 0 && iguana_targetbits(coin,block,prev,prev2,1,coin->chain->targetspacing,coin->chain->targettimespan) != block->RO.bits )
                {
                    printf("nbits target error %x != %x ht.%d\n",iguana_targetbits(coin,block,prev,prev2,1,coin->chain->targetspacing,coin->chain->targettimespan),block->RO.bits,block->height);
                } //else printf(">>>>>>>>>> matched nbits %x ht.%d\n",block->RO.bits,block->height);
                if ( bp->bundleheight+i == coin->blocks.hwmchain.height+1 )
                {
                    //printf("try extend.%d\n",bp->bundleheight+i);
                    //_iguana_chainlink(coin,block); wrong context
                }
                prev2 = prev, prev = block;
            }
        }
        //printf("mapped bundle.%d\n",bp->bundleheight);
        bp->emitfinish = (uint32_t)time(NULL) + 1;
        iguana_bundlecalcs(coin,bp,60);
    }
    else
    {
        //printf("couldnt load bundle.%d\n",bp->bundleheight);
        memset(&bp->ramchain,0,sizeof(bp->ramchain));
        bp->ramchain.height = bp->bundleheight;
        bp->emitfinish = 0;
        //iguana_bundleremove(coin,bp->hdrsi,0);
    }
    if ( mapchain != 0 )
        coin->newramchain++;
    return(mapchain);
}

int64_t iguana_ramchainopen(char *fname,struct iguana_info *coin,struct iguana_ramchain *ramchain,struct OS_memspace *mem,struct OS_memspace *hashmem,int32_t bundleheight,bits256 hash2)
{
    RAMCHAIN_DECLARE; RAMCHAIN_ZEROES; int32_t i,numblocks = coin->chain->bundlesize; uint32_t numtxids,numunspents,numspends,numpkinds,numexternaltxids,scriptspace; struct iguana_bundle *bp; struct iguana_ramchaindata *rdata; int64_t hashsize,allocsize;
    //B = 0, Ux = 0, Sx = 0, P = 0, A = 0, X = 0, Kspace = TXbits = PKbits = 0, U = 0, S = 0, T = 0;
    mem->alignflag = sizeof(uint32_t);
    hashmem->alignflag = sizeof(uint32_t);
    scriptspace = numexternaltxids = numtxids = coin->chain->bundlesize * 1.5;
    numunspents = numspends = numpkinds = numtxids * 2;
    for (i=0; i<coin->bundlescount; i++)
        if ( (bp= coin->bundles[i]) != 0 && (rdata= bp->ramchain.H.data) != 0 )
        {
            if ( rdata->numtxids > numtxids )
                numtxids = rdata->numtxids;
            if ( rdata->numpkinds > numpkinds )
                numpkinds = rdata->numpkinds;
            if ( rdata->numspends > numspends )
                numspends = rdata->numspends;
            if ( rdata->numunspents > numunspents )
                numunspents = rdata->numunspents;
            if ( rdata->numexternaltxids > numexternaltxids )
                numexternaltxids = rdata->numexternaltxids;
            if ( rdata->scriptspace > scriptspace )
                scriptspace = rdata->scriptspace;
        }
#ifndef __APPLE__
    numtxids *= 1.25; numexternaltxids *= 1.25, scriptspace *= 1.25;
    numunspents *= 1.25, numspends *= 1.25, numpkinds *= 1.25;
#endif
    if ( mem->ptr == 0 )
    {
        while ( (allocsize= _iguana_rdata_action(fname,0,0,0,0,1,numtxids,numunspents,numspends,numpkinds,numexternaltxids,scriptspace,0,0,0,0,0,RAMCHAIN_ARG,numblocks,coin->chain->zcash)) > 2*1024LL*1024L*1024L )
        {
            numtxids *= .9;
            numunspents *= .9;
            numspends *= .9;
            numpkinds *= .9;
            numexternaltxids *= .9;
        }
        iguana_meminit(mem,coin->symbol,0,allocsize + 65536*3,0);
    }
    if ( hashmem->ptr == 0 )
    {
        hashsize = iguana_hashmemsize(numtxids,numunspents,numspends,numpkinds,numexternaltxids,scriptspace);
        iguana_meminit(hashmem,coin->symbol,0,hashsize + 65536*3,0);
    }
    if ( iguana_ramchain_init(fname,ramchain,mem,hashmem,1,numtxids,numunspents,numspends,numpkinds,numexternaltxids,scriptspace,1,numblocks,coin->chain->zcash) > 0 )
    {
        iguana_ramchain_link(ramchain,hash2,bundleheight/coin->chain->bundlesize,bundleheight,0,0,1,0);
        ramchain->expanded = 1;
        ramchain->H.scriptoffset = 1;
        _iguana_ramchain_setptrs(RAMCHAIN_PTRS,ramchain->H.data);
        iguana_ramchain_extras(coin,ramchain,hashmem,0);
    }
    if ( rdata != 0 )
        return(rdata->allocsize);
    else return(0);
}

int32_t iguana_mapchaininit(char *fname,struct iguana_info *coin,struct iguana_ramchain *mapchain,struct iguana_bundle *bp,int32_t bundlei,struct iguana_block *block,void *ptr,long filesize)
{
    int32_t firsti = 1; RAMCHAIN_DECLARE;
    memset(mapchain,0,sizeof(*mapchain));
    mapchain->fileptr = ptr;
    mapchain->filesize = filesize;
    mapchain->H.data = (void *)(long)((long)ptr + block->fpos);
    mapchain->H.ROflag = 1;
    if ( ptr == 0 || block->fpos > filesize )
    {
        printf("ptr.%p fpos error %d > %ld mapping hdrsi.%d bundlei.%d\n",ptr,block->fpos,filesize,bp->hdrsi,bundlei);
        return(-1);
    }
    _iguana_ramchain_setptrs(MAPCHAIN_PTRS,mapchain->H.data);
    if ( block->fpos+mapchain->H.data->allocsize > filesize || iguana_ramchain_size(fname,MAPCHAIN_ARG,1,mapchain->H.data->scriptspace,coin->chain->zcash) != mapchain->H.data->allocsize )
    {
        printf("iguana_mapchaininit.%d ipbits.%x size mismatch %ld vs %ld vs filesize.%ld fpos.%ld bundlei.%d expanded.%d soff.%d\n",bp->bundleheight,block->fpipbits,(long)iguana_ramchain_size(fname,MAPCHAIN_ARG,1,mapchain->H.data->scriptspace,coin->chain->zcash),(long)mapchain->H.data->allocsize,(long)filesize,(long)block->fpos,bundlei,mapchain->expanded,mapchain->H.data->scriptspace);
        //getchar();
        return(-1);
    }
    else if ( memcmp(bp->hashes[bundlei].bytes,mapchain->H.data->firsthash2.bytes,sizeof(bits256)) != 0 )
    {
        char str[65],str2[65]; printf("iguana_bundlesaveHT.[%d:%d] hash2 mismatch %s vs %s\n",bp->hdrsi,bundlei,bits256_str(str,bp->hashes[bundlei]),bits256_str(str2,mapchain->H.data->firsthash2));
        return(-1);
    }
    iguana_ramchain_link(mapchain,bp->hashes[bundlei],bp->hdrsi,bp->bundleheight+bundlei,bundlei,1,firsti,1);
    if ( bp->blocks[bundlei]->RO.txn_count == 0 )
        bp->blocks[bundlei]->RO.txn_count = mapchain->H.data->numtxids - 1;
    return(0);
}

// helper threads: NUM_HELPERS
int32_t iguana_bundlesaveHT(struct iguana_info *coin,struct OS_memspace *mem,struct OS_memspace *memB,struct iguana_bundle *bp,uint32_t starttime) // helper thread
{
    static int depth; static const bits256 zero;
    RAMCHAIN_DESTDECLARE; RAMCHAIN_DECLARE; RAMCHAIN_ZEROES;
    void **ptrs; long *filesizes; uint32_t *ipbits; char fname[1024];
    struct iguana_ramchain *R,*mapchain,*dest,newchain; uint32_t fpipbits; bits256 prevhash2;
    int32_t i,starti,bROsize,endi,bp_n,numtxids,valid,sigspace,pubkeyspace,numunspents,numspends,numpkinds,numexternaltxids,scriptspace; struct iguana_block *block; long fpos;
    struct OS_memspace HASHMEM; int32_t err,j,num,hdrsi,bundlei,firsti= 1,retval = -1;
    memset(&HASHMEM,0,sizeof(HASHMEM));
    starti = 0, endi = bp->n - 1;
    //B = 0, Ux = 0, Sx = 0, P = 0, A = 0, X = 0, Kspace = TXbits = PKbits = 0, U = 0, S = 0, T = 0;
    R = mycalloc('s',bp->n,sizeof(*R));
    ptrs = mycalloc('w',bp->n,sizeof(*ptrs));
    ipbits = mycalloc('w',bp->n,sizeof(*ipbits));
    filesizes = mycalloc('f',bp->n,sizeof(*filesizes));
    if ( (num= iguana_bundlefiles(coin,ipbits,ptrs,filesizes,bp,starti,endi)) != bp->n )
    {
        iguana_bundlemapfree(coin,0,0,ipbits,ptrs,filesizes,num,R,starti,endi);
        printf("iguana_bundlesaveHT: no bundlefiles error.[%d]\n",bp->hdrsi);
        return(-1);
    }
    if ( bp == coin->current )
        endi = num-1;
    bp_n = (endi - starti + 1);
    scriptspace = 1;
    sigspace = pubkeyspace = 0;
    if ( (block= bp->blocks[starti]) != 0 )
        prevhash2 = block->RO.prev_block;
    else memset(prevhash2.bytes,0,sizeof(prevhash2));
    for (bundlei=starti,numtxids=numunspents=scriptspace=numspends=0; bundlei<=endi; bundlei++)
    {
        if ( coin->active == 0 )
        {
            iguana_bundlemapfree(coin,mem,&HASHMEM,ipbits,ptrs,filesizes,num,R,starti,endi);
            return(-1);
        }
        if ( (block= bp->blocks[bundlei]) == 0 || bits256_nonz(block->RO.hash2) == 0 || memcmp(block->RO.hash2.bytes,bp->hashes[bundlei].bytes,sizeof(bits256)) != 0 || bits256_cmp(block->RO.prev_block,prevhash2) != 0 ) // block != iguana_blockfind("bundlesave",coin,block->RO.hash2)
        {
            printf("block.%p error vs %p\n",block,iguana_blockfind("bundlesaveerr",coin,block->RO.hash2));
            break;
        }
        fpipbits = block->fpipbits, fpos = block->fpos;
        mapchain = &R[bundlei];
        //printf("mapchain.[%d:%d] %p[%ld]\n",bp->hdrsi,bundlei,ptrs[bundlei],filesizes[bundlei]);
        sprintf(fname,"save.%d",bp->hdrsi);
        if ( iguana_mapchaininit(fname,coin,mapchain,bp,bundlei,block,ptrs[bundlei],filesizes[bundlei]) < 0 )
        {
            iguana_bundlemapfree(coin,0,0,ipbits,ptrs,filesizes,num,R,starti,endi);
            iguana_blockunmark(coin,bp->blocks[bundlei],bp,bundlei,1);
            printf("error mapping hdrsi.%d bundlei.%d\n",bp->hdrsi,bundlei);
            return(-1);
        }
        //printf("done mapchain.[%d:%d]\n",bp->hdrsi,bundlei);
        numtxids += (mapchain->H.data->numtxids - 1);
        numunspents += (mapchain->H.data->numunspents - 1);
        numspends += (mapchain->H.data->numspends - 1);
        scriptspace += 1;//iguana_ramchain_scriptspace(coin,&sigsize,&pubkeysize,mapchain);
        //sigspace += sigsize;
        //pubkeyspace += pubkeysize;
        //printf("%x ",(uint32_t)block->RO.hash2.ulongs[3]);
        _iguana_ramchain_setptrs(MAPCHAIN_PTRS,mapchain->H.data);
        if ( bits256_cmp(B[0].hash2,block->RO.hash2) != 0 )
        {
            printf("mapped chain [%d:%d] hash2 mismatch\n",bp->hdrsi,bundlei);
            break;
        }
        //printf("(%d %d).%d ",mapchain->H.data->numtxids,bp->blocks[bundlei]->RO.txn_count,numtxids);
        //printf("%d ",numtxids);
        prevhash2 = block->RO.hash2;
    }
    scriptspace += pubkeyspace*1.1 + sigspace*1.1;
    //printf("mem.%p mapchain txid tables, scriptspace.%u sigspace.%u pubkeyspace.%u bundlei.%d/%d\n",mem,scriptspace,sigspace,pubkeyspace,bundlei,bp->n);
    if ( bundlei != endi+1 )
    {
        iguana_bundlemapfree(coin,0,0,ipbits,ptrs,filesizes,num,R,starti,endi);
        iguana_blockunmark(coin,bp->blocks[bundlei],bp,bundlei,1);
        printf("error mapping hdrsi.%d bundlei.%d\n",bp->hdrsi,bundlei);
        return(-1);
    }
    dest = &bp->ramchain;
    //printf("iguana_bundlesaveHT.%d -> total (%d %d %d) scriptspace.%d (pubkeys.%d sigs.%d) dest->txids %p\n",bp->bundleheight,numtxids,numunspents,numspends,scriptspace,pubkeyspace,sigspace,dest->txids);
    dest->txids = dest->pkhashes = 0;
    numpkinds = numunspents;
    numexternaltxids = numspends;
    //printf("E.%d depth.%d start bundle ramchain %d at %u started.%u lag.%d\n",coin->numemitted,depth,bp->bundleheight,now,starttime,now-starttime);
    depth++;
    if ( iguana_ramchain_alloc(fname,coin,dest,mem,&HASHMEM,numtxids,numunspents,numspends,numpkinds,numexternaltxids,scriptspace+sigspace,bp->bundleheight+starti,bp_n,coin->chain->zcash) < 0 )
    {
        printf("error iguana_ramchain_alloc for bundleheight.%d\n",bp->bundleheight);
        iguana_bundlemapfree(coin,mem,&HASHMEM,ipbits,ptrs,filesizes,num,R,starti,endi);
        return(-1);
    }
    iguana_ramchain_link(dest,bp->hashes[starti],bp->hdrsi,bp->bundleheight,0,bp->n,firsti,0);
    dest->expanded = 1;
    dest->H.scriptoffset = 1;
    _iguana_ramchain_setptrs(RAMCHAIN_DESTPTRS,dest->H.data);
    iguana_ramchain_extras(coin,dest,&HASHMEM,0);
    bROsize = (int32_t)(sizeof(struct iguana_blockRO) + coin->chain->zcash*sizeof(struct iguana_msgblockhdr_zcash));
    for (i=starti; i<=endi; i++)
    {
        if ( coin->active == 0 )
        {
            iguana_bundlemapfree(coin,mem,&HASHMEM,ipbits,ptrs,filesizes,num,R,starti,endi);
            return(-1);
        }
        if ( (block= bp->blocks[i]) != 0 )//&& block == iguana_blockfind("saveHT",coin,bp->hashes[i]) )
        {
            if ( bits256_nonz(block->RO.prev_block) == 0 && i > 0 )
                block->RO.prev_block = bp->hashes[i-1];
            if ( (bp->bundleheight+i > 0 && bits256_nonz(block->RO.prev_block) == 0) || iguana_blockvalidate(coin,&valid,block,1) < 0 )
            {
                char str[65]; printf("null prevblock error at ht.%d patch.(%s)\n",bp->bundleheight+i,bits256_str(str,bp->hashes[i-1]));
                iguana_bundlemapfree(coin,mem,&HASHMEM,ipbits,ptrs,filesizes,num,R,starti,endi);
                iguana_blockunmark(coin,block,bp,i,1);
                return(-1);
            }
            destB[i] = block->RO;
            //memcpy((void *)((long)destB + i*bROsize),&block->RO,bROsize);
        } else printf("error getting block (%d:%d) %p vs %p\n",bp->hdrsi,i,block,bp->blocks[i]);
    }
    dest->H.txidind = dest->H.unspentind = dest->H.spendind = dest->pkind = dest->H.data->firsti;
    dest->externalind = dest->H.stacksize = 0;
    dest->H.scriptoffset = 1;
    for (bundlei=starti; bundlei<=endi; bundlei++)
    {
        if ( coin->active == 0 )
            break;
        if ( (block= bp->blocks[bundlei]) != 0 )
        {
            iguana_blocksetcounters(coin,block,dest);
            //coin->blocks.RO[bp->bundleheight+bundlei] = block->RO;
            memcpy((void *)((long)destB + bundlei*bROsize),&block->RO,bROsize);//[bundlei] = block->RO;
            //destB[bundlei] = block->RO;
            //fprintf(stderr,"(%d %d).%d ",R[bundlei].H.data->numtxids,dest->H.txidind,bundlei);
            if ( (err= iguana_ramchain_iterate(coin,dest,&R[bundlei],bp,bundlei)) != 0 )
            {
                if ( (block= bp->blocks[bundlei]) != 0 )
                {
                    iguana_bundlemapfree(coin,mem,&HASHMEM,ipbits,ptrs,filesizes,num,R,starti,endi);
                    iguana_blockunmark(coin,block,bp,bundlei,1);
                    return(-1);
                }
                if ( coin->active != 0 )
                    printf("error ramchain_iterate hdrs.%d bundlei.%d\n",bp->hdrsi,bundlei);
                break;
            }
        }
        else
        {
            printf("error ramchain_iterate hdrs.%d bundlei.%d cant find block\n",bp->hdrsi,bundlei);
            break;
        }
    }
    if ( dest->H.scriptoffset > dest->H.data->scriptspace )
    {
        printf("bundlesave: stack smashed %d+%d > %d\n",dest->H.scriptoffset,dest->H.stacksize,dest->H.data->scriptspace);
        bundlei = -1;
    }
    //printf(" about to save dest scriptoffset.%d stacksize.%d data scriptspace.%d\n",dest->H.scriptoffset,dest->H.stacksize,dest->H.data->scriptspace);
    depth--;
    memset(&newchain,0,sizeof(newchain));
    if ( bundlei == endi+1 && iguana_ramchain_expandedsave(coin,RAMCHAIN_DESTARG,&newchain,&HASHMEM,0,bp) == 0 )
    {
        //char str[65]; printf("d.%d ht.%d %s saved lag.%d elapsed.%ld\n",depth,dest->height,mbstr(str,dest->H.data->allocsize),now-starttime,time(NULL)-now);
        retval = 0;
    } else bp->generrs++;
    iguana_bundlemapfree(coin,mem,&HASHMEM,ipbits,ptrs,filesizes,num,R,starti,endi);
    if ( retval == 0 )
    {
        //char dirname[1024];
        printf("delete %d files hdrs.[%d] retval.%d bp_n.%d\n",num,bp->hdrsi,retval,bp_n);
        if ( iguana_bundleload(coin,&newchain,bp,0) == 0 )
            retval = -1;
        else if ( bp_n == bp->n && bp->n == coin->chain->bundlesize && bp->hdrsi < coin->bundlescount-3 )
        {
            for (j=starti; j<=endi; j++)
            {
                if ( iguana_peerfname(coin,&hdrsi,GLOBAL_TMPDIR,fname,0,bp->hashes[j],zero,1,1) >= 0 )
                    coin->peers->numfiles -= OS_removefile(fname,0);
                else printf("error removing.(%s)\n",fname);
            }
            //sprintf(dirname,"%s/%s/%d",GLOBAL_TMPDIR,coin->symbol,bp->bundleheight), OS_portable_rmdir(dirname,1);
        }
        //sleep(1);
        newchain.A = 0;
    }
    if ( coin->active != 0 )
    {
        iguana_ramchain_free(coin,dest,0);
        bp->ramchain = newchain;
    }
    //printf("finished bundlesave.%d retval.%d\n",bp->bundleheight,retval);
    return(retval);
}

void iguana_mergefree(struct iguana_info *coin,struct OS_memspace *mem,struct iguana_ramchain *A,struct iguana_ramchain *B,struct OS_memspace *hashmem,struct OS_memspace *hashmemA,struct OS_memspace *hashmemB)
{
    if ( A != 0 )
        iguana_ramchain_free(coin,A,0);
    if ( B != 0 )
        iguana_ramchain_free(coin,B,0);
    if ( mem != 0 )
        iguana_mempurge(mem);
    if ( hashmemA != 0 )
        iguana_mempurge(hashmemA);
    if ( hashmemB != 0 )
        iguana_mempurge(hashmemB);
}

int32_t iguana_bundlemergeHT(char *fname,struct iguana_info *coin,struct OS_memspace *mem,struct OS_memspace *memB,struct iguana_bundle *bp,struct iguana_bundle *nextbp,uint32_t starttime)
{
    static int32_t depth; static const bits256 zero;
    RAMCHAIN_DESTDECLARE; struct OS_memspace HASHMEM,HASHMEMA,HASHMEMB;
    uint32_t now = (uint32_t)time(NULL); char str[65],fnameA[1024],fnameB[1024];
    struct iguana_ramchain _Achain,_Bchain,*A,*B,R,newchain,*dest = &R; int32_t err,retval = -1,firsti = 1;
    memset(mem,0,sizeof(*mem));
    memset(&HASHMEMA,0,sizeof(HASHMEMA));
    iguana_meminit(&HASHMEMA,"hashmemA",0,iguana_hashmemsize(bp->ramchain.H.txidind,bp->ramchain.H.unspentind,bp->ramchain.H.spendind,bp->ramchain.pkind,bp->ramchain.externalind,bp->ramchain.H.data->scriptspace) + IGUANA_MAXSCRIPTSIZE,0);
    memset(&HASHMEMB,0,sizeof(HASHMEMB));
    iguana_meminit(&HASHMEMB,"hashmemB",0,iguana_hashmemsize(nextbp->ramchain.H.txidind,nextbp->ramchain.H.unspentind,nextbp->ramchain.H.spendind,nextbp->ramchain.pkind,nextbp->ramchain.externalind,nextbp->ramchain.H.data->scriptspace) + IGUANA_MAXSCRIPTSIZE,0);
    memset(&_Achain,0,sizeof(_Achain)); A = &_Achain;
    memset(&_Bchain,0,sizeof(_Bchain)); B = &_Bchain;
    if ( (A= iguana_ramchain_map(coin,fnameA,bp,bp->ramchain.numblocks,A,&HASHMEMA,0,bp->hashes[0],zero,0,0,1,1)) != 0 )
    {
        iguana_ramchain_link(A,bp->hashes[0],bp->hdrsi,bp->bundleheight,0,bp->ramchain.numblocks,firsti,1);
    }
    if ( (B= iguana_ramchain_map(coin,fnameB,bp,nextbp->ramchain.numblocks,B,&HASHMEMB,0,nextbp->hashes[0],zero,0,0,1,1)) != 0 )
    {
        iguana_ramchain_link(B,bp->hashes[0],nextbp->hdrsi,nextbp->bundleheight,0,nextbp->ramchain.numblocks,firsti,1);
    }
    if ( A == 0 || B == 0 || A->H.data == 0 || B->H.data == 0 || (A->H.data->allocsize + B->H.data->allocsize) > IGUANA_MAXRAMCHAINSIZE )
    {
        printf("MERGE error %d[%d] %d[%d]\n",A->height,A->numblocks,B->height,B->numblocks);
        iguana_mergefree(coin,mem,A,B,&HASHMEM,&HASHMEMA,&HASHMEMB);
        return(-1);
    }
    if ( A->H.data != 0 && B->H.data != 0 && B->height == A->height+A->numblocks )
    {
        if ( iguana_ramchain_alloc(fname,coin,dest,mem,&HASHMEM,(A->H.data->numtxids+B->H.data->numtxids),(A->H.data->numunspents+B->H.data->numunspents),(A->H.data->numspends+B->H.data->numspends),(A->H.data->numpkinds+B->H.data->numpkinds),(A->H.data->numexternaltxids+B->H.data->numexternaltxids),A->H.data->scriptspace,A->height,A->numblocks + B->numblocks,coin->chain->zcash) < 0 )
        {
            printf("depth.%d ht.%d fsize.%s ERROR alloc lag.%d elapsed.%ld\n",depth,dest->height,mbstr(str,dest->H.data->allocsize),now-starttime,time(NULL)-now);
            iguana_mergefree(coin,mem,A,B,&HASHMEM,&HASHMEMA,&HASHMEMB);
            return(-1);
        }
        depth++;
        iguana_ramchain_link(dest,A->H.data->firsthash2,A->H.hdrsi,A->height,0,A->numblocks+B->numblocks,firsti,0);
        _iguana_ramchain_setptrs(RAMCHAIN_DESTPTRS,dest->H.data);
        iguana_ramchain_extras(coin,dest,&HASHMEM,0);
        dest->H.txidind = dest->H.unspentind = dest->H.spendind = dest->pkind = dest->H.data->firsti;
        dest->externalind = 0;
        if ( (err= iguana_ramchain_iterate(coin,dest,A,bp,-1)) != 0 )
            printf("error.%d ramchain_iterate A.%d\n",err,A->height);
        else if ( (err= iguana_ramchain_iterate(coin,dest,B,nextbp,-1)) != 0 )
            printf("error.%d ramchain_iterate B.%d\n",err,B->height);
        else if ( iguana_ramchain_expandedsave(coin,RAMCHAIN_DESTARG,&newchain,&HASHMEM,0,0) == 0 )
        {
            printf("merging isnt setup to save the blockROs\n");
            printf("depth.%d ht.%d fsize.%s MERGED %d[%d] and %d[%d] lag.%d elapsed.%ld bp.%d -> %d\n",depth,dest->height,mbstr(str,dest->H.data->allocsize),A->height,A->numblocks,B->height,B->numblocks,now-starttime,time(NULL)-now,bp->bundleheight,nextbp->bundleheight);
            iguana_mergefree(coin,mem,A,B,&HASHMEM,&HASHMEMA,&HASHMEMB);
            bp->mergefinish = 0;
            nextbp->mergefinish = (uint32_t)time(NULL);
            bp->nextbp = nextbp->nextbp;
            newchain.hashmem = 0;
            retval = 0;
            nextbp->ramchain = bp->ramchain = newchain;
            OS_removefile(fnameA,0);
            OS_removefile(fnameB,0);
        }
        else
        {
            bp->mergefinish = nextbp->mergefinish = 0;
            iguana_mergefree(coin,mem,A,B,&HASHMEM,&HASHMEMA,&HASHMEMB);
        }
        iguana_ramchain_free(coin,dest,0);
        depth--;
    } else printf("error merging A.%d [%d] and B.%d [%d]\n",A->height,A->numblocks,B->height,B->numblocks);
    coin->merging--;
    return(retval);
}

#ifdef later
void iguana_ramchainmerge(struct iguana_info *coin) // jl777: verify prev/next hash2
{
    struct iguana_bundle *bp,*nextbp,*A,*B; int64_t total = 0; int32_t n,flag = 0;
    if ( coin->bundlescount <= 0 || coin->merging > 0 )
        return;
    A = B = 0;
    n = 0;
    bp = coin->bundles[0];
    while ( bp != 0 && (nextbp= bp->nextbp) != 0 )
    {
        n++;
        if ( nextbp != 0 && bp != 0 && bp->emitfinish > 1 && nextbp->emitfinish > 1 && bp->mergefinish == 0 && nextbp->mergefinish == 0 && bp->ramchain.datasize + nextbp->ramchain.datasize < IGUANA_MAXRAMCHAINSIZE )
        {
            if ( total == 0 || (bp->ramchain.datasize + nextbp->ramchain.datasize) < total )
            {
                total = (bp->ramchain.datasize + nextbp->ramchain.datasize);
                A = bp, B = nextbp;
            }
        }
        bp = nextbp;
    }
    if ( A != 0 && B != 0 )
    {
        bp = A, nextbp = B;
        bp->mergefinish = nextbp->mergefinish = 1;
        flag++;
        char str[65]; printf("start merge %d[%d] + %d[%d] %s\n",bp->bundleheight,bp->ramchain.numblocks,nextbp->bundleheight,nextbp->ramchain.numblocks,mbstr(str,bp->ramchain.datasize + nextbp->ramchain.datasize));
        coin->merging++;
        iguana_mergeQ(coin,bp,nextbp);
    }
    if ( flag != 0 )
    {
        bp = coin->bundles[0];
        while ( bp != 0 && (nextbp= bp->nextbp) != 0 )
        {
            printf("%d[%d].%d ",bp->bundleheight,bp->ramchain.numblocks,bp->mergefinish);
            bp = nextbp;
        }
        printf("bundles.%d\n",n);
    }
}
#endif
