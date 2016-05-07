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

#include "iguana777.h"
#include "SuperNET.h"

//struct iguana_txid { bits256 txid; uint32_t txidind,firstvout,firstvin,locktime,version,timestamp; uint16_t numvouts,numvins; } __attribute__((packed));

//struct iguana_msgvin { bits256 prev_hash; uint8_t *script; uint32_t prev_vout,scriptlen,sequence; } __attribute__((packed));

//struct iguana_spend { uint32_t spendtxidind; int16_t prevout; uint16_t tbd:14,external:1,diffsequence:1; } __attribute__((packed));

int32_t iguana_scriptdata(struct iguana_info *coin,uint8_t *scriptspace,long fileptr[2],char *fname,uint64_t scriptpos,int32_t scriptlen)
{
    FILE *fp; long err; int32_t retval = scriptlen;
#ifndef __PNACL__
    if ( scriptpos < 0xffffffff )
    {
        if ( fileptr[0] == 0 )
            fileptr[0] = (long)OS_mapfile(fname,&fileptr[1],0);
        if ( fileptr[0] != 0 )
        {
            if ( (scriptpos + scriptlen) <= fileptr[1] )
            {
                memcpy(scriptspace,(void *)(fileptr[0] + (uint32_t)scriptpos),scriptlen);
                return(retval);
            }
            else if ( 0 )
            {
                printf("munmap (%s)\n",fname);
                munmap((void *)fileptr[0],fileptr[1]);
                fileptr[0] = fileptr[1] = 0;
            }
        }
    }
#else
    static portable_mutex_t mutex;
    portable_mutex_lock(&mutex);
#endif
    if ( (fp= fopen(fname,"rb")) != 0 )
    {
        fseek(fp,scriptpos,SEEK_SET);
        if ( (err= fread(scriptspace,1,scriptlen,fp)) != scriptlen )
        {
            retval = -1;
            printf("%s script[%d] offset.%llu err.%ld\n",fname,scriptlen,(long long)scriptpos,err);
        } //else printf("%s script[%d] offset.%llu read.%ld\n",fname,scriptlen,(long long)scriptpos,err);
        fclose(fp);
    } else retval = -1;
#ifdef __PNACL__
    portable_mutex_unlock(&mutex);
#endif
    return(retval);
}

int32_t iguana_vinset(struct iguana_info *coin,uint8_t *scriptspace,int32_t height,struct iguana_msgvin *vin,struct iguana_txid *tx,int32_t i)
{
    struct iguana_spend *s,*S; uint32_t spendind,unspentind; bits256 *X; struct iguana_bundle *bp;
    struct iguana_ramchaindata *rdata; struct iguana_txid *T; char fname[1024]; int32_t scriptlen,err = 0;
    memset(vin,0,sizeof(*vin));
    if ( height >= 0 && height < coin->chain->bundlesize*coin->bundlescount && (bp= coin->bundles[height / coin->chain->bundlesize]) != 0 && (rdata= bp->ramchain.H.data) != 0 )
    {
        S = RAMCHAIN_PTR(rdata,Soffset);
        X = RAMCHAIN_PTR(rdata,Xoffset);
        T = RAMCHAIN_PTR(rdata,Toffset);
        //S = (void *)(long)((long)rdata + rdata->Soffset);
        //X = (void *)(long)((long)rdata + rdata->Xoffset);
        //T = (void *)(long)((long)rdata + rdata->Toffset);
        spendind = (tx->firstvin + i);
        s = &S[spendind];
        vin->sequence = s->sequenceid;
        vin->prev_vout = s->prevout;
        if ( s->scriptpos != 0 && s->scriptlen > 0 )
        {
            iguana_vinsfname(coin,bp->ramchain.from_ro,fname,s->fileid);
            if ( (scriptlen= iguana_scriptdata(coin,scriptspace,coin->peers.vinptrs[s->fileid],fname,s->scriptpos,s->scriptlen)) != s->scriptlen )
                printf("err.%d getting %d bytes from fileid.%llu[%d] %s for s%d\n",err,s->scriptlen,(long long)s->scriptpos,s->fileid,fname,spendind);
        }
        vin->scriptlen = s->scriptlen;
        vin->vinscript = scriptspace;
        iguana_ramchain_spendtxid(coin,&unspentind,&vin->prev_hash,T,rdata->numtxids,X,rdata->numexternaltxids,s);
    }
    if ( err != 0 )
        return(-err);
    else return(vin->scriptlen);
}

int32_t iguana_voutscript(struct iguana_info *coin,struct iguana_bundle *bp,uint8_t *scriptspace,char *asmstr,struct iguana_unspent *u,struct iguana_pkhash *p,int32_t txi)
{
    struct vin_info V; char fname[1024],coinaddr[65]; int32_t scriptlen = -1;
    if ( u->scriptpos > 0 && u->scriptlen > 0 )
    {
        iguana_voutsfname(coin,bp->ramchain.from_ro,fname,u->fileid);
        if ( (scriptlen= iguana_scriptdata(coin,scriptspace,coin->peers.voutptrs[u->fileid],fname,u->scriptpos,u->scriptlen)) != u->scriptlen )
            printf("%d bytes from fileid.%d[%d] %s for type.%d\n",u->scriptlen,u->fileid,u->scriptpos,fname,u->type);
    }
    else
    {
        memset(&V,0,sizeof(V));
        scriptlen = iguana_scriptgen(coin,&V.M,&V.N,coinaddr,scriptspace,asmstr,p->rmd160,u->type,(const struct vin_info *)&V,txi);
    }
    return(scriptlen);
}

int32_t iguana_voutset(struct iguana_info *coin,uint8_t *scriptspace,char *asmstr,int32_t height,struct iguana_msgvout *vout,struct iguana_txid *tx,int32_t i)
{
    struct iguana_ramchaindata *rdata; uint32_t unspentind,scriptlen = 0; struct iguana_bundle *bp;
    struct iguana_unspent *u,*U; struct iguana_pkhash *P; int32_t err = 0;
    memset(vout,0,sizeof(*vout));
    if ( height >= 0 && height < coin->chain->bundlesize*coin->bundlescount && (bp= coin->bundles[height / coin->chain->bundlesize]) != 0  && (rdata= bp->ramchain.H.data) != 0 && i < tx->numvouts )
    {
        U = RAMCHAIN_PTR(rdata,Uoffset);
        P = RAMCHAIN_PTR(rdata,Poffset);
        //U = (void *)(long)((long)rdata + rdata->Uoffset);
        //P = (void *)(long)((long)rdata + rdata->Poffset);
        unspentind = (tx->firstvout + i);
        u = &U[unspentind];
        if ( u->txidind != tx->txidind || u->vout != i || u->hdrsi != height / coin->chain->bundlesize )
            printf("iguana_voutset: txidind mismatch %d vs %d || %d vs %d || (%d vs %d)\n",u->txidind,u->txidind,u->vout,i,u->hdrsi,height / coin->chain->bundlesize);
        vout->value = u->value;
        vout->pk_script = scriptspace;
        scriptlen = iguana_voutscript(coin,bp,scriptspace,asmstr,u,&P[u->pkind],i);
    } else printf("iguana_voutset unexpected path\n");
    vout->pk_scriptlen = scriptlen;
    if ( err != 0 )
        return(-err);
    else return(scriptlen);
}

struct iguana_txid *iguana_blocktx(struct iguana_info *coin,struct iguana_txid *tx,struct iguana_block *block,int32_t i)
{
    struct iguana_bundle *bp; uint32_t txidind;
    if ( i >= 0 && i < block->RO.txn_count )
    {
        if ( block->height >= 0 )
        {
            if ( (bp= coin->bundles[block->hdrsi]) != 0 )
            {
                if ( (txidind= block->RO.firsttxidind) > 0 )
                {
                    if ( iguana_bundletx(coin,bp,block->bundlei,tx,txidind+i) == tx )
                        return(tx);
                    printf("error getting txidind.%d + i.%d from hdrsi.%d\n",txidind,i,block->hdrsi);
                    return(0);
                } // else printf("iguana_blocktx null txidind [%d:%d] i.%d\n",block->hdrsi,block->bundlei,i);
            } else printf("iguana_blocktx no bp.[%d]\n",block->hdrsi);
        } else printf("blocktx illegal height.%d\n",block->height);
    } else printf("i.%d vs txn_count.%d\n",i,block->RO.txn_count);
    return(0);
}

int32_t iguana_ramtxbytes(struct iguana_info *coin,uint8_t *serialized,int32_t maxlen,bits256 *txidp,struct iguana_txid *tx,int32_t height,struct iguana_msgvin *vins,struct iguana_msgvout *vouts,int32_t validatesigs)
{
    int32_t i,rwflag=1,len = 0; char asmstr[512],txidstr[65];
    uint32_t numvins,numvouts; struct iguana_msgvin vin; struct iguana_msgvout vout; uint8_t space[IGUANA_MAXSCRIPTSIZE];
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(tx->version),&tx->version);
    if ( coin->chain->hastimestamp != 0 )
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(tx->timestamp),&tx->timestamp);
    numvins = tx->numvins, numvouts = tx->numvouts;
    len += iguana_rwvarint32(rwflag,&serialized[len],&numvins);
    memset(&vin,0,sizeof(vin));
    for (i=0; i<numvins; i++)
    {
        if ( vins == 0 )
            iguana_vinset(coin,space,height,&vin,tx,i);
        else vin = vins[i];
        if ( validatesigs != 0 && iguana_validatesigs(coin,&vin) < 0 )
        {
            printf("error validating vin.%d ht.%d\n",i,height);
            return(0);
        }
        len += iguana_rwvin(rwflag,0,&serialized[len],&vin);
    }
    if ( len > maxlen )
        return(0);
    len += iguana_rwvarint32(rwflag,&serialized[len],&numvouts);
    for (i=0; i<numvouts; i++)
    {
        if ( vouts == 0 )
            iguana_voutset(coin,space,asmstr,height,&vout,tx,i);
        else vout = vouts[i];
        len += iguana_rwvout(rwflag,0,&serialized[len],&vout);
    }
    if ( len > maxlen )
        return(0);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(tx->locktime),&tx->locktime);
    *txidp = bits256_doublesha256(txidstr,serialized,len);
    if ( memcmp(txidp,tx->txid.bytes,sizeof(*txidp)) != 0 )
    {
        //for (i=0; i<len; i++)
        //    printf("%02x",serialized[i]);
        //char str[65],str2[65]; printf("\nrw.%d numvins.%d numvouts.%d error generating txbytes txid %s vs %s\n",rwflag,numvins,numvouts,bits256_str(str,*txidp),bits256_str(str2,tx->txid));
        return(-1);
    }
    return(len);
}

int32_t iguana_peerblockrequest(struct iguana_info *coin,uint8_t *blockspace,int32_t max,struct iguana_peer *addr,bits256 hash2,int32_t validatesigs)
{
    struct iguana_txid *tx,T; bits256 checktxid; int32_t i,len,total,bundlei=-2; struct iguana_block *block; struct iguana_msgblock msgB; bits256 *tree,checkhash2,merkle_root; struct iguana_bundle *bp=0; long tmp; char str[65];
    if ( (bp= iguana_bundlefind(coin,&bp,&bundlei,hash2)) != 0 && bundlei >= 0 && bundlei < bp->n )
    {
        if ( (block= bp->blocks[bundlei]) != 0 )
        {
            iguana_blockunconv(&msgB,block,1);
            total = iguana_rwblock(1,&checkhash2,&blockspace[sizeof(struct iguana_msghdr) + 0],&msgB);
            if ( bits256_cmp(checkhash2,block->RO.hash2) != 0 )
            {
                printf("iguana_peerblockrequest: blockhash mismatch ht.%d\n",bp->bundleheight+bundlei);
                return(-1);
            }
            for (i=0; i<block->RO.txn_count; i++)
            {
                if ( (tx= iguana_blocktx(coin,&T,block,i)) != 0 )
                {
                    if ( (len= iguana_ramtxbytes(coin,&blockspace[sizeof(struct iguana_msghdr) + total],max - total,&checktxid,tx,block->height,0,0,validatesigs)) > 0 && bits256_cmp(checktxid,T.txid) == 0 )
                        total += len;
                    else
                    {
                        char str[65],str2[65];
                        printf("error getting txi.%d [%d:%d] cmp.%s %s\n",i,bp->hdrsi,bundlei,bits256_str(str,checktxid),bits256_str(str2,T.txid));
                        break;
                    }
                }
                else
                {
                    //printf("null tx error getting txi.%d [%d:%d]\n",i,bp->hdrsi,bundlei);
                    break;
                }
            }
            if ( i == block->RO.txn_count )
            {
                tmp = (long)&blockspace[sizeof(struct iguana_msghdr) + total + sizeof(bits256)];
                tmp &= ~(sizeof(bits256) - 1);
                tree = (void *)tmp;
                for (i=0; i<block->RO.txn_count; i++)
                {
                    if ( (tx= iguana_blocktx(coin,&T,block,i)) != 0 )
                        tree[i] = T.txid;
                    else break;
                }
                if ( i == block->RO.txn_count )
                {
                    merkle_root = iguana_merkle(coin,tree,block->RO.txn_count);
                    if ( bits256_cmp(merkle_root,block->RO.merkle_root) == 0 )
                    {
                        if ( addr != 0 )
                        {
                            printf("Send block.%d to %s\n",total,addr->ipaddr);
                            return(iguana_queue_send(coin,addr,0,blockspace,"block",total,0,0));
                        }
                        else
                        {
                            //printf("validated.[%d:%d] len.%d\n",bp->hdrsi,bundlei,total);
                            return(total);
                        }
                    } else printf("iguana_peerblockrequest: error merkle cmp tx.[%d] for ht.%d\n",i,bp->bundleheight+bundlei);
                } else printf("iguana_peerblockrequest: error merkle verify tx.[%d] for ht.%d\n",i,bp->bundleheight+bundlei);
            } //else printf("iguana_peerblockrequest: error getting tx.[%d] for ht.%d block.%p main.%d ht.%d\n",i,bp->bundleheight+bundlei,block,block!=0?block->mainchain:-1,block!=0?block->height:-1);
        }
        else
        {
            if ( block != 0 )
                printf("iguana_peerblockrequest: block.%p ht.%d mainchain.%d [%d:%d]\n",block,block->height,block->mainchain,bp->hdrsi,bundlei);
            else printf("iguana_peerblockrequest: block.%p [%d:%d]\n",block,bp->hdrsi,bundlei);
        }
    } else printf("iguana_peerblockrequest: cant find %s\n",bits256_str(str,hash2));
    return(-1);
}

cJSON *iguana_blockjson(struct iguana_info *coin,struct iguana_block *block,int32_t txidsflag)
{
    char str[65],hexstr[1024]; int32_t i,len,size; struct iguana_txid *tx,T; struct iguana_msgblock msg;
    bits256 hash2,nexthash2; uint8_t serialized[1024]; cJSON *array,*json = cJSON_CreateObject();
    jaddstr(json,"result","success");
    jaddstr(json,"blockhash",bits256_str(str,block->RO.hash2));
    jaddnum(json,"height",block->height);
    //jaddnum(json,"ipbits",block->fpipbits);
    jaddstr(json,"merkleroot",bits256_str(str,block->RO.merkle_root));
    jaddstr(json,"previousblockhash",bits256_str(str,block->RO.prev_block));
    if ( block->height > 0 )
    {
        nexthash2 = iguana_blockhash(coin,block->height+1);
        if ( bits256_nonz(nexthash2) != 0 )
            jaddstr(json,"nextblockhash",bits256_str(str,nexthash2));
    }
    jaddnum(json,"timestamp",block->RO.timestamp);
    jaddstr(json,"utc",utc_str(str,block->RO.timestamp));
    jaddnum(json,"nonce",block->RO.nonce);
    jaddnum(json,"version",block->RO.version);
    jaddnum(json,"numvouts",block->RO.numvouts);
    jaddnum(json,"numvins",block->RO.numvins);
    jaddnum(json,"recvlen",block->RO.recvlen);
    jaddnum(json,"hdrsi",block->hdrsi);
    jaddnum(json,"PoW",block->PoW);
    jaddnum(json,"bundlei",block->bundlei);
    jaddnum(json,"mainchain",block->mainchain);
    jaddnum(json,"valid",block->valid);
    jaddnum(json,"txn_count",block->RO.txn_count);
    
    jaddnum(json,"bits",block->RO.bits);
    serialized[0] = ((uint8_t *)&block->RO.bits)[3];
    serialized[1] = ((uint8_t *)&block->RO.bits)[2];
    serialized[2] = ((uint8_t *)&block->RO.bits)[1];
    serialized[3] = ((uint8_t *)&block->RO.bits)[0];
    init_hexbytes_noT(hexstr,serialized,sizeof(uint32_t));
    jaddstr(json,"nBitshex",hexstr);
    memset(&msg,0,sizeof(msg));
    msg.H.version = block->RO.version;
    msg.H.merkle_root = block->RO.merkle_root;
    msg.H.timestamp = block->RO.timestamp;
    msg.H.bits = block->RO.bits;
    msg.H.nonce = block->RO.nonce;
    msg.txn_count = 0;//block->RO.txn_count;
    len = iguana_rwblock(1,&hash2,serialized,&msg);
    init_hexbytes_noT(hexstr,serialized,len);
    jaddstr(json,"blockheader",hexstr);
    if ( txidsflag != 0 )
    {
        array = cJSON_CreateArray();
        for (i=0; i<block->RO.txn_count; i++)
        {
            if ( (tx= iguana_blocktx(coin,&T,block,i)) != 0 )
                jaddistr(array,bits256_str(str,tx->txid));
        }
        jadd(json,"tx",array);
        //printf("add txids[%d]\n",block->txn_count);
    }
    if ( (size= iguana_peerblockrequest(coin,coin->blockspace,sizeof(coin->blockspace),0,block->RO.hash2,0)) < 0 )
        jaddstr(json,"error","couldnt generate raw bytes for block");
    else jaddnum(json,"size",size);
    return(json);
}

