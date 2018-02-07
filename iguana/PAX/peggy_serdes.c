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

int32_t serdes777_rwbits(int32_t rwflag,void *ptr,int32_t len,HUFF *hp)
{
    int32_t i,bit;
    if ( rwflag == 0 )
    {
        for (i=0; i<len; i++)
        {
            if ( (bit= hgetbit(hp)) < 0 )
                return(-1);
            if ( bit != 0 )
                SETBIT(ptr,i);
            else CLEARBIT(ptr,i);
        }
        //printf("rbits.%d (%02x)\n",len,*(uint8_t *)ptr);
    }
    else
    {
        //printf("wbits.%d (%02x)\n",len,*(uint8_t *)ptr);
        for (i=0; i<len; i++)
            if ( hputbit(hp,GETBIT(ptr,i) != 0) < 0 )
                return(-100*i-100);
    }
    //printf("rwbits len.%d (%02x)\n",len,*(uint8_t *)dest);
    //printf("(%d) ",*(uint8_t *)ptr);
    return(len);
}

int32_t serdes777_rwsizebits(int32_t rwflag,void *xptr,uint64_t xval,int32_t sizebits,HUFF *hp)
{
    int32_t numbits = 0;
    if ( 1 && sizebits == 3 )
    {
        if ( rwflag != 0 )
        {
            if ( xval == 0 )
            {
                hputbit(hp,0);
                return(1);
            }
            else
            {
                hputbit(hp,1);
                if ( xval < 3 )
                {
                    hputbit(hp,(xval&1) != 0);
                    hputbit(hp,(xval&2) != 0);
                    //hputbit(hp,(xval&4) != 0);
                    return(3);
                }
                else
                {
                    hputbit(hp,1), hputbit(hp,1);//, hputbit(hp,1);
                    if ( serdes777_rwbits(1,xptr,8,hp) != 8 )
                        return(-30);
                    return(11);
                }
            }
        }
        else
        {
            if ( hgetbit(hp) == 0 )
            {
                *(uint8_t *)xptr = 0;
                return(1);
            }
            else
            {
                numbits = hgetbit(hp) + (hgetbit(hp) << 1);// + (hgetbit(hp) << 2);
                if ( numbits < 3 )
                {
                    *(uint8_t *)xptr = numbits;
                    return(3);
                }
                else
                {
                    if ( serdes777_rwbits(0,xptr,8,hp) != 8 )
                        return(-4);
                    return(11);
                }
            }
        }
    }
    else
    {
        if ( rwflag != 0 )
        {
            numbits = hcalc_bitsize(xval) - 1;
            //printf("rwsizebits.%d numbits.%d %02x %llu\n",sizebits,numbits,*(uint8_t *)xptr,(long long)xval);
            if ( numbits >= (1 << sizebits) )
            {
                printf("numbits overflow.%d doesnt fit into sizebits.%d\n",numbits,sizebits);
                return(-10);
            }
        }
        if ( serdes777_rwbits(rwflag,&numbits,sizebits,hp) != sizebits )
            return(-20);
        if ( serdes777_rwbits(rwflag,xptr,numbits+1,hp) != numbits+1 )
            return(-30);
        //printf("return.(%02x) numbits.%d + 1 + sizebits.%d\n",*(uint8_t *)xptr,numbits,sizebits);
        //printf("(%02x) ",*(uint8_t *)xptr);
        return(numbits + 1 + sizebits);
    }
}

#define serdes777_rwchar(rwflag,x,hp) serdes777_rwsizebits(rwflag,xptr,*(uint8_t *)xptr,3,hp)
#define serdes777_rwshort(rwflag,x,hp) serdes777_rwsizebits(rwflag,xptr,*(uint16_t *)xptr,4,hp)
#define serdes777_rwint(rwflag,x,hp) serdes777_rwsizebits(rwflag,xptr,*(uint32_t *)xptr,5,hp)
#define serdes777_rwlong(rwflag,x,hp) serdes777_rwsizebits(rwflag,xptr,*(uint64_t *)xptr,6,hp)

int32_t serdes777_convstr(int32_t encoding,void *dest,void *src,int32_t len)
{
    if ( encoding == 16 )
    {
        len >>= 1;
        decode_hex(dest,len,src);
        return(8 * len);
    }
    else if ( encoding == -16 )
    {
        init_hexbytes_noT(dest,src,len);
        return(8 * ((len << 1) + 1));
    }
    else if ( encoding == 32 )
        return(decode_base32(dest,src,len));
    else if ( encoding == -32 )
        return(init_base32(dest,src,len));
    return(-1);
}

int32_t serdes777_rwvarstr(int32_t rwflag,uint8_t *data,int32_t *lenp,HUFF *hp)
{
    int32_t i,n,numbits,total; void *xptr = lenp;
    if ( (total= serdes777_rwchar(rwflag,lenp,hp)) < 0 )
        return(total);
    n = *lenp;
    for (i=0; i<n; i++)
    {
        xptr = &data[i];
        if ( (numbits= serdes777_rwchar(rwflag,&data[i],hp)) < 0 )
            return(-1);
        total += numbits;
    }
    return(total);
}

int32_t serdes777_rwstr(int32_t rwflag,uint8_t *data,HUFF *hp,int32_t encoding)
{
    int32_t total,len; uint8_t *ptr,buf[MAX_OPRETURNSIZE*2 + 1];
    if ( rwflag == 0 )
    {
        ptr = (encoding != 0) ? buf : data;
        if ( (total= serdes777_rwvarstr(rwflag,ptr,&len,hp)) < 0 )
            return(-1);
        if ( encoding != 0 )
            total = serdes777_convstr(-encoding,data,ptr,total);
    }
    else
    {
        len = (int32_t)strlen((void *)data);
        if ( encoding != 0 )
        {
            if ( (len= serdes777_convstr(encoding,buf,data,len)) < 0 )
            {
                printf("serdes777_writestr error doing serdes777_convstr encoding.%d len.%d\n",encoding,len);
                return(-1);
            }
            if ( (len & 7) != 0 )
            {
                printf("serdes777_writestr error doing serdes777_convstr encoding.%d len.%d unaligned return\n",encoding,len);
                return(-1);
            }
            data = (void *)buf;
        }
        total = serdes777_rwvarstr(rwflag,data,&len,hp);
    }
    return(total);
}

int32_t serdes777_rw(int32_t rwflag,void *xptr,int32_t size,HUFF *hp)
{
    if ( size < 0 ) // high entropy
        return(serdes777_rwbits(rwflag,xptr,-size*8,hp));
    //else return(serdes777_rwbits(rwflag,xptr,size*8,hp));
    switch ( size )
    {
        case 1: return(serdes777_rwchar(rwflag,xptr,hp)); break;
        case 2: return(serdes777_rwshort(rwflag,xptr,hp)); break;
        case 4: return(serdes777_rwint(rwflag,xptr,hp)); break;
        case 8: return(serdes777_rwlong(rwflag,xptr,hp)); break;
        default: return(serdes777_rwstr(rwflag,xptr,hp,size)); break;
    }
    return(-1);
}

int32_t serdes777_codec(int32_t rwflag,void *ptr,int32_t maxlen,long tokens[][2],long numtokens,HUFF *hp)
{
    int32_t i,numbits,totalbits = 0;
    // printf("peggy_rwtx.%d %p max.%d %p numtokens.%ld %p\n",rwflag,tx,maxlen,txtokens,numtokens,hp);
    for (i=0; i<numtokens; i++)
    {
        //printf("i.%d peggy_rwtx.%d %p max.%d %p numtokens.%ld %p (%ld %ld)\n",i,rwflag,ptr,maxlen,tokens,numtokens,hp,tokens[i][0],tokens[i][1]);
        if ( (numbits= serdes777_rw(rwflag,(void *)((long)ptr + tokens[i][0]),(int32_t)tokens[i][1],hp)) < 0 )
            return(-i-1);
        totalbits += numbits;
    }
    return(totalbits);
}

int32_t serdes777_rwlock(int32_t rwflag,struct peggy_lock *lock,HUFF *TX)
{
    long serdes777_locktokens[][2] =
    {
        { 0, sizeof(lock->peg) }, { (long)&lock->denom - (long)lock, sizeof(lock->denom) },
        { (long)&lock->minlockdays - (long)lock, sizeof(lock->minlockdays) }, { (long)&lock->maxlockdays - (long)lock, sizeof(lock->maxlockdays) },
        { (long)&lock->clonesmear - (long)lock, sizeof(lock->clonesmear) }, { (long)&lock->mixrange - (long)lock, sizeof(lock->mixrange) },
        { (long)&lock->margin - (long)lock, sizeof(lock->margin) },
    };
    return(serdes777_codec(rwflag,lock,sizeof(*lock),serdes777_locktokens,sizeof(serdes777_locktokens)/sizeof(*serdes777_locktokens),TX));
}

int32_t serdes777_rwaddr(int32_t rwflag,union peggy_addr *addr,int32_t type,HUFF *TX)
{
    int32_t n,numbits = 0;
    switch ( type )
    {
        case PEGGY_ADDRBTCD: numbits = serdes777_rw(rwflag,&addr->coinaddr,0,TX); break;
        case PEGGY_ADDRNXT: numbits = serdes777_rw(rwflag,&addr->nxt64bits,(int32_t)-sizeof(addr->nxt64bits),TX); break;
        case PEGGY_ADDRCREATE:
            if ( (numbits= serdes777_rw(rwflag,&addr->newunit.sha256.bytes,(int32_t)-sizeof(addr->newunit.sha256),TX)) < 0 )
                return(-3);
            if ( (n= serdes777_rwlock(rwflag,&addr->newunit.newlock,TX)) < 0 )
                return(-2);
            numbits += n;
            break;
        case PEGGY_ADDRUNIT:
        case PEGGY_ADDRPUBKEY:
            if ( (numbits= serdes777_rw(rwflag,&addr->newunit.sha256.bytes,(int32_t)-sizeof(addr->newunit.sha256),TX)) < 0 )
                return(-3);
            if ( (n= serdes777_rw(rwflag,&addr->newunit.newlock.peg,sizeof(addr->newunit.newlock.peg),TX)) < 0 )
                return(-2);
            if ( (n= serdes777_rw(rwflag,&addr->newunit.newlock.minlockdays,sizeof(addr->newunit.newlock.minlockdays),TX)) < 0 )
                return(-2);
        case PEGGY_ADDR777:
            numbits = serdes777_rw(rwflag,&addr->SaMbits.bytes,(int32_t)-sizeof(addr->SaMbits),TX); break;
        default: numbits = -1; break;
    }
    return(numbits);
}

int32_t serdes777_rwbets(int32_t rwflag,struct peggy_txbet *bets,int32_t numbets,HUFF *TX)
{
    long serdes777_bettokens[][2] =
    {
        { 0, sizeof(bets[0].prediction) },
        { (long)&bets[0].peg - (long)bets, 0 },
        { (long)&bets[0].binary - (long)bets, sizeof(bets[0].binary) }
    };
    int32_t i,n,numbits = 0;
    if ( numbets <= 0 )
        return(0);
    for (i=0; i<numbets; i++)
    {
        if ( (n= serdes777_codec(rwflag,&bets[i],sizeof(bets[i]),serdes777_bettokens,sizeof(serdes777_bettokens)/sizeof(*serdes777_bettokens),TX)) < 0 )
            return(-1);
        numbits += n;
    }
    return(numbits);
}

int32_t serdes777_rwmicropay(int32_t rwflag,struct peggy_txmicropay *micropay,int32_t num,HUFF *TX)
{
    long serdes777_mptokens[][2] =
    {
        { 0, sizeof(micropay[0].claimhash) },
        { (long)&micropay[0].refundhash - (long)micropay, sizeof(micropay[0].refundhash) },
        { (long)&micropay[0].expiration - (long)micropay, sizeof(micropay[0].expiration) },
        { (long)&micropay[0].chainlen - (long)micropay, sizeof(micropay[0].chainlen) },
        { (long)&micropay[0].vin - (long)micropay, sizeof(micropay[0].vin) },
        { (long)&micropay[0].vout - (long)micropay, sizeof(micropay[0].vout) },
    };
    int32_t i,n,numbits = 0;
    if ( num <= 0 )
        return(0);
    for (i=0; i<num; i++)
    {
        if ( (n= serdes777_codec(rwflag,&micropay[i],sizeof(micropay[i]),serdes777_mptokens,sizeof(serdes777_mptokens)/sizeof(*serdes777_mptokens),TX)) < 0 )
            return(-1);
        numbits += n;
    }
    return(numbits);
}

int32_t serdes777_rwinout(int32_t rwflag,int32_t inoutflag,void *inout,HUFF *TX)
{
    int32_t type,a,b,c,d; struct peggy_input *in; struct peggy_output *out;
    if ( inoutflag == 0 )
    {
        in = inout;
        a = serdes777_rw(rwflag,&in->type,sizeof(in->type),TX);
        b = serdes777_rw(rwflag,&in->chainlen,sizeof(in->chainlen),TX);
        c = serdes777_rwaddr(rwflag,&in->src,in->type,TX);
        d = serdes777_rw(rwflag,&in->amount,sizeof(in->amount),TX);
        type = in->type;
    }
    else
    {
        out = inout;
        a = serdes777_rw(rwflag,&out->type,sizeof(out->type),TX);
        b = serdes777_rw(rwflag,&out->vin,sizeof(out->vin),TX);
        c = serdes777_rwaddr(rwflag,&out->dest,out->type,TX);
        d = serdes777_rw(rwflag,&out->ratio,sizeof(out->ratio),TX);
        type = out->type;
    }
    if ( a < 0 || b < 0 || c < 0 || d < 0 )
    {
        printf("serdes777_rwinput.%d error encoding type.%d %d %d %d %d\n",rwflag,type,a,b,c,d);
        //getchar();
        return(-1);
    }
    return(a + b + c + d);
}

int32_t serdes777_rwprices(int32_t rwflag,struct peggy_txprices *price,HUFF *TX)
{
    long serdes777_pricetokens[][2] =
    {
        { 0, sizeof(price->num) }, //{ (long)&prices->btcusd - (long)prices, sizeof(prices->btcusd) },
        { (long)&price->timestamp - (long)price, sizeof(price->timestamp) },
        { (long)&price->maxlockdays - (long)price, sizeof(price->maxlockdays) }
    };
    long serdes777_pricetoken2[][2] = { { 0, sizeof(price->feed[0]) } };
    int32_t i,n,numbits = -1;
    if ( (numbits= serdes777_codec(rwflag,&price->num,sizeof(price->num),serdes777_pricetokens,sizeof(serdes777_pricetokens)/sizeof(*serdes777_pricetokens),TX)) < 0 )
        return(-1);
    //printf("numprices.%u btcusd %.6f: ",prices->num,(double)1000.*prices->btcusd);
    for (i=0; i<price->num; i++)
    {
        if ( (n= serdes777_codec(rwflag,&price->feed[i],sizeof(price->feed[i]),serdes777_pricetoken2,sizeof(serdes777_pricetoken2)/sizeof(*serdes777_pricetoken2),TX)) < 0 )
            return(-1);
        //printf("(%d of %d %u) ",i,prices->num,prices->prices[i]);
        numbits += n;
    }
    return(numbits);
}

int32_t serdes777_rwtune(int32_t rwflag,struct peggy_txtune *tune,int32_t numtunes,HUFF *TX)
{
    long serdes777_tunetokens[][2] =
    {
        { 0, sizeof(tune[0].type) },
        { (long)&tune[0].peg - (long)tune, 0 },
        { (long)&tune[0].val - (long)tune, sizeof(tune[0].val) },
        { (long)&tune[0].B - (long)tune, sizeof(tune[0].B) },
    };
    int32_t i,n,numbits = -1;
    if ( numtunes <= 0 )
        return(0);
    for (i=0; i<numtunes; i++)
    {
        if ( (n= serdes777_codec(rwflag,&tune[i],sizeof(tune[i]),serdes777_tunetokens,sizeof(serdes777_tunetokens)/sizeof(*serdes777_tunetokens),TX)) < 0 )
            return(-1);
        numbits += n;
    }
    return(numbits);
}

int32_t serdes777_rwdetails(int32_t rwflag,struct peggy_tx *Ptx,HUFF *TX)
{
    int32_t n,numbits = 0;
    //printf("rwdetails.%d offset.%d txtype.%d\n",rwflag,TX->bitoffset,Ptx->txtype);
    switch ( Ptx->txtype )
    {
        case PEGGY_TXBET: numbits = serdes777_rwbets(rwflag,Ptx->details.bets,Ptx->numdetails,TX); break;
        case PEGGY_TXPRICES: numbits = serdes777_rwprices(rwflag,&Ptx->details.price,TX); break;
        case PEGGY_TXTUNE: break; numbits = serdes777_rwtune(rwflag,Ptx->details.tune,Ptx->numdetails,TX); break;
        case PEGGY_TXMICROPAY:  numbits = serdes777_rwmicropay(rwflag,Ptx->details.micropays,Ptx->numdetails,TX); break;
    }
    if ( numbits < 0 )
        return(-1);
    if ( Ptx->msglen != 0 )
    {
        if ( (n = serdes777_rwstr(rwflag,(uint8_t *)Ptx->hexstr,TX,16)) < 0 )
            return(-1);
        numbits += n;
    }
    return(numbits);
}

int32_t serdes777_sethdrtokens(long serdes777_hdrtokens[][2],struct peggy_tx *Ptx)
{
    long hdrtokens[][2] =
    {
        { 0, -sizeof(Ptx->datalen) },
        { (long)&Ptx->numinputs - (long)Ptx, sizeof(Ptx->numinputs) },
        { (long)&Ptx->numoutputs - (long)Ptx, sizeof(Ptx->numoutputs) },
        { (long)&Ptx->txtype - (long)Ptx, sizeof(Ptx->txtype) },
        { (long)&Ptx->flags - (long)Ptx, sizeof(Ptx->flags) },
        { (long)&Ptx->msglen - (long)Ptx, sizeof(Ptx->msglen) },
        { (long)&Ptx->numdetails - (long)Ptx, sizeof(Ptx->numdetails) },
        { (long)&Ptx->timestamp - (long)Ptx, sizeof(Ptx->timestamp) },
        { (long)&Ptx->activation - (long)Ptx, sizeof(Ptx->activation) },
        { (long)&Ptx->expiration - (long)Ptx, sizeof(Ptx->expiration) },
    };
    memcpy(serdes777_hdrtokens,hdrtokens,sizeof(hdrtokens));
    return((int32_t)(sizeof(hdrtokens)/sizeof(*hdrtokens)));
}

int32_t serdes777_rwtx(int32_t rwflag,struct peggy_tx *Ptx,HUFF *TX)
{
    int32_t i,n,iter,numbits,totalbits = 0; void *ptr; long serdes777_hdrtokens[16][2];
    //printf("peggy_rwtx.%d %p %p size.%d\n",rwflag,Ptx,TX,TX->endpos);
    if ( (totalbits= serdes777_codec(rwflag,Ptx,sizeof(*Ptx),serdes777_hdrtokens,serdes777_sethdrtokens(serdes777_hdrtokens,Ptx),TX)) < 0 )
    {
        printf("serdes777_process error decoding opreturn datalen.%d hdrtokens\n",totalbits);
        return(-1);
    }
    if ( (Ptx->flags & PEGGY_FLAGS_HASFUNDING) != 0 )
    {
        if ( (numbits= serdes777_rwinout(rwflag,0,&Ptx->funding,TX)) < 0 )
        {
            printf("serdes777_process error serdes.%d funding %.8f %p\n",rwflag,dstr(Ptx->funding.amount),&Ptx->funding.src.coinaddr);
            return(-1);
        }
        totalbits += numbits;
    }
    n = Ptx->numinputs;
    for (iter=0; iter<2; iter++)
    {
        for (i=0; i<n; i++)
        {
            if ( iter == 0 )
                ptr = &Ptx->inputs[i];
            else ptr = &Ptx->outputs[i];
            if ( (numbits= serdes777_rwinout(rwflag,iter,ptr,TX)) < 0 )
            {
                printf("serdes777_process error serdes.%d input.%d\n",rwflag,i);
                return(-1);
            }
            totalbits += numbits;
            printf("%d iter.%d .%d\n",i,iter,totalbits/8);
        }
        n = Ptx->numoutputs;
    }
    if ( (numbits= serdes777_rwdetails(rwflag,Ptx,TX)) < 0 )
    {
        printf("serdes777_process error serdes777_rwdetails.%d datalen.%d\n",i,totalbits);
        return(-1);
    }
    totalbits += numbits;
    return(totalbits);
}

int serdes777_checktimestamp(uint32_t blocktimestamp,uint32_t timestamp)
{
    if ( blocktimestamp == 0 || timestamp == 0 )
        return(0);
    else if ( timestamp < ((int64_t)blocktimestamp - PEGGY_PASTSTAMP) || timestamp > ((int64_t)blocktimestamp + PEGGY_FUTURESTAMP) )
        return(-1);
    return(0);
}

int32_t serdes777_deserialize(int32_t *signedcountp,struct peggy_tx *Ptx,uint32_t blocktimestamp,uint8_t *data,int32_t totallen)
{
    int32_t i,n,len,totalbits,remains; HUFF TX;
    memset(Ptx,0,sizeof(*Ptx));
    memcpy(Ptx->data,data,totallen);
    memset(&TX,0,sizeof(TX)), _init_HUFF(&TX,totallen,data), TX.endpos = (totallen * 8);
    if ( (totalbits= serdes777_rwtx(0,Ptx,&TX)) < 0 )
        return(-1);
    if ( serdes777_checktimestamp(blocktimestamp,Ptx->timestamp) < 0 )
    {
        printf("serdes777_deserialize: timestamp.%u too different from Ptx %u %d\n",blocktimestamp,Ptx->timestamp,blocktimestamp - Ptx->timestamp);
        return(-1);
    }
    if ( (len= (int32_t)hconv_bitlen(totalbits)) > totallen )
    {
        printf("serdes777_process error totalbits.%d len.%d exceeded totallen.%d\n",totalbits,len,totallen);
        return(-1);
    }
    Ptx->datalen = len;
    //for (i=0; i<len; i++)
    //    printf("%02x",Ptx->data[i]);
    //printf(" crc.%08x datalen.%d vs totallen.%d\n",_crc32(0,Ptx->data,len),len,totallen);
    remains = (totallen - len);
    if ( (remains % sizeof(bits256)) != 0 )
    {
        printf("serdes777_process error totalbits.%d remains.%d nonzero modval.%d\n",totalbits,remains,(int32_t)(remains % sizeof(bits256)));
        return(-1);
    }
    n = (int32_t)(remains / sizeof(bits256));
    //printf("n.%d remains.%d\n",n,remains);
    if ( n > 0 )
    {
        if ( Ptx->numinputs == 1 && Ptx->inputs[0].type == PEGGY_ADDRPUBKEY && n == 1 )
        {
            memcpy(Ptx->sigs[0].sigbits.bytes,&data[len],sizeof(bits256)), len += sizeof(bits256);
            Ptx->sigs[0].pubkey = Ptx->inputs[0].src.sha256;
        }
        else
        {
            for (i=0; i<n; i++,len+=sizeof(bits256))
                memcpy((i & 1) == 0 ? Ptx->sigs[i/2].sigbits.bytes :  Ptx->sigs[i/2].pubkey.bytes,&data[len],sizeof(bits256));
        }
        for (i=0; i<n; i++)
        {
            if ( Ptx->sigs[i].sigbits.txid != 0 )
            {
                if ( (Ptx->sigs[i].signer64bits= PAX_validate(&Ptx->sigs[i],Ptx->timestamp,Ptx->data,Ptx->datalen)) == 0 )
                {
                    printf("Tx validation error at sig.%d\n",i);
                    return(-1);
                }
                (*signedcountp)++;
                printf("len.%d verify.%d t%u %llx %llu\n",len,i,Ptx->timestamp,(long long)Ptx->sigs[i].sigbits.txid,(long long)Ptx->sigs[i].signer64bits);
            }
            else break;
        }
    }
    return(len);
}

int32_t serdes777_serialize(struct peggy_tx *Ptx,uint32_t blocktimestamp,bits256 privkey,uint32_t timestamp)
{
    int32_t i,len,numbits; HUFF TX;
    memset(Ptx->data,0,sizeof(Ptx->data));
    memset(&TX,0,sizeof(TX)), _init_HUFF(&TX,sizeof(Ptx->data),Ptx->data);
    if ( Ptx->timestamp == 0 )
        Ptx->timestamp = timestamp;
    else if ( timestamp != 0 && serdes777_checktimestamp(blocktimestamp,timestamp) < 0 )
    {
        printf("serdes777_serialize: timestamp.%u too different from Ptx %u %d\n",timestamp,Ptx->timestamp,timestamp - Ptx->timestamp);
        return(-1);
    }
    if ( (numbits= serdes777_rwtx(1,Ptx,&TX)) < 0 )
        return(-1);
    //printf("TX.bitoffset.%d\n",TX.bitoffset);
    len = (int32_t)hconv_bitlen(TX.bitoffset);
    Ptx->datalen = len;
    hseek(&TX,0,SEEK_SET);
    if ( serdes777_rw(1,&Ptx->datalen,-(int32_t)sizeof(Ptx->datalen),&TX) < 0 )
        return(-1);
    //for (i=0; i<len; i++)
    //    printf("%02x",Ptx->data[i]);
    //printf(" crc.%08x datalen.%d\n",_crc32(0,Ptx->data,len),len);
    for (i=0; i<sizeof(Ptx->sigs)/sizeof(*Ptx->sigs); i++)
    {
        //printf("scan sig.%d\n",i);
        if ( Ptx->sigs[i].sigbits.txid == 0 )
            break;
        if ( PAX_validate(&Ptx->sigs[i],Ptx->timestamp,Ptx->data,len) != Ptx->sigs[i].signer64bits )
        {
            printf("Tx validation error at sig.%d\n",i);
            return(-1);
        }
        memcpy(&Ptx->data[len],Ptx->sigs[i].sigbits.bytes,sizeof(Ptx->sigs[i].sigbits)), len += sizeof(Ptx->sigs[i].sigbits);
        memcpy(&Ptx->data[len],Ptx->sigs[i].pubkey.bytes,sizeof(Ptx->sigs[i].pubkey)), len += sizeof(Ptx->sigs[i].pubkey);
    }
    if ( i < sizeof(Ptx->sigs)/sizeof(*Ptx->sigs)-1 && Ptx->timestamp != 0 && privkey.txid != 0 )
    {
        Ptx->sigs[i].signer64bits = PAX_signtx(&Ptx->sigs[i],privkey,Ptx->timestamp,Ptx->data,len);
        printf("len.%d sign sig.%d %llx %llu t%u\n",len,i,(long long)Ptx->sigs[i].sigbits.txid,(long long)Ptx->sigs[i].signer64bits,Ptx->timestamp);
        memcpy(&Ptx->data[len],Ptx->sigs[i].sigbits.bytes,sizeof(Ptx->sigs[i].sigbits)), len += sizeof(Ptx->sigs[i].sigbits);
        memcpy(&Ptx->data[len],Ptx->sigs[i].pubkey.bytes,sizeof(Ptx->sigs[i].pubkey)), len += sizeof(Ptx->sigs[i].pubkey);
        if ( Ptx->sigs[i].signer64bits != PAX_validate(&Ptx->sigs[i],Ptx->timestamp,Ptx->data,Ptx->datalen) )
        {
            printf("Tx validation error at sig.%d\n",i);
            //return(-1);
        }
        printf("len.%d verify.%d t%u %llx %llu\n",len,i,Ptx->timestamp,(long long)Ptx->sigs[i].sigbits.txid,(long long)Ptx->sigs[i].signer64bits);
    } //else printf("skip signing t%u %llu\n",timestamp,(long long)privkey.txid);
    return(len);
}

int32_t accts777_parse(union peggy_addr *addr,cJSON *item,int32_t type)
{
    int32_t peggy_setname(char *buf,char *name);
    char name[16],*coinaddr,*hashstr; struct peggy_lock *lock;
    if ( item == 0 )
        return(-1);
    switch ( type )
    {
        case PEGGY_ADDRBTCD:
            if ( (coinaddr= jstr(item,"BTCD")) != 0 && peggy_addr2univ(&addr->coinaddr,coinaddr,"BTCD") < 0 )
            {
                printf("illegal coinaddr.(%s)\n",coinaddr);
                return(-1);
            }
            break;
        case PEGGY_ADDRCREATE:
            if ( (hashstr= jstr(item,"lockhash")) != 0 && strlen(hashstr) == 64 )
                decode_hex(addr->newunit.sha256.bytes,sizeof(bits256),hashstr);
            lock = &addr->newunit.newlock;
            lock->peg = peggy_setname(name,jstr(item,"peg"));
            lock->denom = jint(item,"denom");
            lock->minlockdays = jint(item,"minlockdays");
            lock->maxlockdays = jint(item,"maxlockdays");
            lock->clonesmear = jint(item,"clonesmear");
            lock->mixrange = jint(item,"mixrange");
            lock->margin = jint(item,"margin");
            break;
        case PEGGY_ADDRNXT:
            addr->nxt64bits = j64bits(item,"NXT");
            break;
        case PEGGY_ADDRUNIT:
            if ( (hashstr= jstr(item,"unithash")) != 0 && strlen(hashstr) == 64 )
                decode_hex(addr->sha256.bytes,sizeof(bits256),hashstr);
            break;
        case PEGGY_ADDR777:
            if ( (hashstr= jstr(item,"SaMbits")) != 0 && strlen(hashstr) == 96 )
                decode_hex(addr->SaMbits.bytes,sizeof(bits384),hashstr);
            break;
        case PEGGY_ADDRPUBKEY:
            if ( (hashstr= jstr(item,"unlockpubkey")) != 0 && strlen(hashstr) == 64 )
                decode_hex(addr->newunit.sha256.bytes,sizeof(bits256),hashstr);
            lock = &addr->newunit.newlock;
            lock->peg = peggy_setname(name,jstr(item,"peg"));
            lock->minlockdays = lock->maxlockdays = jint(item,"lockdays");
            if ( jint(item,"denom") < 0 )
                lock->peg = -lock->peg;
            break;
    }
    return(0);
}

int32_t peggy_inputs(struct peggy_tx *Ptx,cJSON *array)
{
    int32_t i,n = 0; cJSON *item;
    if ( array != 0 && (n= cJSON_GetArraySize(array)) > 0 )
    {
        for (i=0; i<n&&i<PEGGY_MAXINPUTS; i++)
        {
            item = jitem(array,i);
            Ptx->inputs[i].type = juint(item,"type");
            Ptx->inputs[i].chainlen = juint(item,"chainlen");
            Ptx->inputs[i].amount = juint(item,"amount");
            accts777_parse(&Ptx->inputs[i].src,item,Ptx->inputs[i].type);
        }
    }
    return(n);
}

int32_t peggy_outputs(struct peggy_tx *Ptx,cJSON *array)
{
    int32_t i,n=0; cJSON *item;
    if ( array != 0 && (n= cJSON_GetArraySize(array)) > 0 )
    {
        for (i=0; i<n&&i<PEGGY_MAXOUTPUTS; i++)
        {
            item = jitem(array,i);
            Ptx->outputs[i].type = juint(item,"type");
            Ptx->outputs[i].vin = juint(item,"vin");
            Ptx->outputs[i].ratio = juint(item,"ratio");
            accts777_parse(&Ptx->outputs[i].dest,item,Ptx->outputs[i].type);
        }
    }
    return(n);
}

int32_t peggy_details(struct peggy_tx *Ptx,cJSON *json,int32_t txtype,uint32_t btcusd)
{
    struct destbuf name;
    int32_t i,n=0; cJSON *item,*array; char *hashstr,*refundstr; struct peggy_txtune *tune; struct peggy_txmicropay *mp; struct peggy_txbet *bet;
    Ptx->details.price.timestamp = juint(json,"genesistime");
    Ptx->details.price.maxlockdays = juint(json,"maxlockdays");
    //printf("BTCUSD.%d vs %d\n",Ptx->details.prices.btcusd,btcusd);
    if ( (array= jarray(&n,json,"details")) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
    {
        if ( txtype == PEGGY_TXPRICES )
            Ptx->details.price.num = n;
        for (i=0; i<n; i++)
        {
            item = jitem(array,i);
            switch ( txtype )
            {
                case PEGGY_TXNORMAL:
                    break;
                case PEGGY_TXBET:
                    bet = &Ptx->details.bets[i];
                    copy_cJSON(&name,jobj(item,"peg"));
                    safecopy(bet->peg,name.buf,sizeof(bet->peg));
                    bet->binary = juint(item,"binary");
                    bet->prediction.Pval = juint(item,"prediction");
                    break;
                case PEGGY_TXPRICES:
                    Ptx->details.price.feed[i] = juint(item,0);
                    break;
                case PEGGY_TXTUNE:
                    tune = &Ptx->details.tune[i];
                    copy_cJSON(&name,jobj(item,"peg"));
                    safecopy(tune->peg,name.buf,sizeof(bet->peg));
                    tune->type = juint(item,"type");
                    tune->val = j64bits(item,"val");
                    tune->B.val = j64bits(item,"valB");
                    tune->B.bytes[0] = j64bits(item,"interesttenths");
                    tune->B.bytes[1] = j64bits(item,"posboost");
                    tune->B.bytes[2] = j64bits(item,"negpenalty");
                    tune->B.bytes[3] = j64bits(item,"feediv");
                    tune->B.bytes[4] = j64bits(item,"feemult");
                    break;
                case PEGGY_TXMICROPAY:
                    mp = &Ptx->details.micropays[i];
                    if ( (hashstr= jstr(item,"claimhash")) != 0 && strlen(hashstr) == 64 )
                        decode_hex(mp->claimhash.bytes,sizeof(bits256),hashstr);
                    if ( (refundstr= jstr(item,"refundhash")) != 0 && strlen(refundstr) == 64 )
                        decode_hex(mp->refundhash.bytes,sizeof(bits256),refundstr);
                    mp->expiration = juint(item,"expiration");
                    mp->chainlen = juint(item,"chainlen");
                    mp->vin = juint(item,"vin");
                    mp->vout = juint(item,"vout");
                    break;
            }
        }
    }
    return(0);
}

char *peggy_tx(char *jsonstr)
{
    cJSON *json; int32_t i,n,len,signedcount; char *hexstr,opreturnstr[8192],retbuf[4096],retbufstr[8192],checkstr[8192];
    struct peggy_tx Ptx,checkPtx; bits256 privkey; struct destbuf tmp;
    memset(&Ptx,0,sizeof(Ptx));
    opreturnstr[0] = 0;
    memset(privkey.bytes,0,sizeof(privkey));
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        printf("(%s)\n",jsonstr);
        Ptx.flags = juint(json,"flags");
        Ptx.txtype = juint(json,"txtype");
        Ptx.numinputs = peggy_inputs(&Ptx,jarray(&n,json,"inputs"));
        Ptx.numoutputs = peggy_outputs(&Ptx,jarray(&n,json,"outputs"));
        if ( Ptx.txtype != PEGGY_TXNORMAL )
            Ptx.numdetails = peggy_details(&Ptx,json,Ptx.txtype,juint(json,"btcusd"));
        if ( (hexstr= jstr(json,"privkey")) != 0 && strlen(hexstr) == 64 )
            decode_hex(privkey.bytes,sizeof(privkey),hexstr);
        //else printf("no privkey.%p (%s)\n",hexstr,jsonstr);
        if ( (hexstr= jstr(json,"hexstr")) != 0 && strlen(hexstr) < sizeof(Ptx.hexstr) )
            strcpy(Ptx.hexstr,hexstr), Ptx.msglen = (int32_t)strlen(hexstr)/2;
        Ptx.activation = juint(json,"activation");
        Ptx.expiration = juint(json,"expiration");
        if ( (Ptx.funding.amount= juint(json,"funds")) != 0 )
        {
            copy_cJSON(&tmp,jobj(json,"fundsaddr"));
            //safecopy(Ptx.funding.src.coinaddr,tmp.buf,sizeof(Ptx.funding.src.coinaddr));
            if ( peggy_addr2univ(&Ptx.funding.src.coinaddr,tmp.buf,"BTCD") < 0 )
            {
                printf("warning: illegal funding address.(%s)\n",tmp.buf);
            }
            Ptx.flags |= PEGGY_FLAGS_HASFUNDING;
            Ptx.funding.type = PEGGY_ADDRFUNDING;
        }
        Ptx.timestamp = (uint32_t)time(NULL);
        len = serdes777_serialize(&Ptx,Ptx.timestamp,privkey,Ptx.timestamp);
        init_hexbytes_noT(opreturnstr,Ptx.data,len);
        //printf("datalen.%d (%s).%ld\n",Ptx.datalen,opreturnstr,strlen(opreturnstr));
        /*if ( PEGS != 0 && peggy_txind(&tipvalue,PEGS->accts,0,Ptx.timestamp,0,&Ptx,fundsvalue,fundsaddr) < 0 )
         {
         printf("%s\nerror validating tx\n",opreturnstr);
         //return(clonestr("\"error\":\"error validating tx\"}"));
         }*/
        len = serdes777_deserialize(&signedcount,&checkPtx,Ptx.timestamp,Ptx.data,len);
        retbuf[0] = OP_RETURN_OPCODE;
        if ( len+3 < 0xfe )
        {
            retbuf[1] = len+3;
            strcpy(retbuf+2,"PAX");
            memcpy(retbuf+5,Ptx.data,len);
            init_hexbytes_noT(retbufstr,(void *)retbuf,len+5);
        }
        else
        {
            retbuf[1] = 0xfe;
            retbuf[2] = (len+3) & 0xff;
            retbuf[3] = ((len+3) >> 8) & 0xff;
            strcpy(retbuf+4,"PAX");
            memcpy(retbuf+7,Ptx.data,len);
            init_hexbytes_noT(retbufstr,(void *)retbuf,len+7);
        }
        init_hexbytes_noT(checkstr,checkPtx.data,len);
        if ( strcmp(checkstr,opreturnstr) != 0 )
        {
            for (i=0; i<Ptx.datalen; i++)
                if ( checkstr[i] != opreturnstr[i] )
                    printf("(%02x != %02x).%d ",checkstr[i],opreturnstr[i],i);
            printf("%s Ptx\n%s check\npeggy_tx ser/deser error datalen.%d\n",opreturnstr,checkstr,checkPtx.datalen);
            return(clonestr("\"error\":\"ser/deser error\"}"));
        }
        //else printf("peggy_tx success\n%s\n%s\n",opreturnstr,checkstr);
        free_json(json);
        //printf("%s\n",retbufstr);
        return(clonestr(retbufstr));
    }
    return(clonestr("\"error\":\"couldnt create opreturn\"}"));
}


