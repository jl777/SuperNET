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
#include "../includes/iguana_apidefs.h"

STRING_ARG(iguana,initfastfind,activecoin)
{
    if ( (coin= iguana_coinfind(activecoin)) != 0 )
    {
        iguana_fastfindcreate(coin);
        return(clonestr("{\"result\":\"fast find initialized\"}"));
    } else return(clonestr("{\"error\":\"no coin to initialize\"}"));
}

TWO_STRINGS_AND_TWO_DOUBLES(iguana,balance,activecoin,address,lastheightd,minconfd)
{
    int32_t lastheight,minconf,maxconf=SATOSHIDEN; int64_t total=0; uint8_t rmd160[20],pubkey33[33],addrtype;
    struct iguana_pkhash *P; cJSON *array,*retjson = cJSON_CreateObject();
    if ( activecoin != 0 && activecoin[0] != 0 )
        coin = iguana_coinfind(activecoin);
    if ( coin != 0 )
    {
        if ( (minconf= minconfd) <= 0 )
            minconf = 1;
        lastheight = lastheightd;
        jaddstr(retjson,"address",address);
        if ( bitcoin_validaddress(coin,address) < 0 )
        {
            jaddstr(retjson,"error","illegal address");
            return(jprint(retjson,1));
        }
        if ( bitcoin_addr2rmd160(&addrtype,rmd160,address) < 0 )
        {
            jaddstr(retjson,"error","cant convert address");
            return(jprint(retjson,1));
        }
        memset(pubkey33,0,sizeof(pubkey33));
        P = calloc(coin->bundlescount,sizeof(*P));
        array = cJSON_CreateArray();
        //printf("Start %s balance.(%s) height.%d\n",coin->symbol,address,lastheight);
        if ( lastheight == 0 )
            lastheight = IGUANA_MAXHEIGHT;
        iguana_pkhasharray(myinfo,coin,array,minconf,maxconf,&total,P,coin->bundlescount,rmd160,address,pubkey33,lastheight,0,0,0,remoteaddr);
        free(P);
        jadd(retjson,"unspents",array);
        jaddnum(retjson,"balance",dstr(total));
        if ( lastheight > 0 )
            jaddnum(retjson,"lastheight",lastheight);
    }
    return(jprint(retjson,1));
}

STRING_ARG(iguana,validate,activecoin)
{
    int32_t i,total,validated; struct iguana_bundle *bp; cJSON *retjson;
    if ( (coin= iguana_coinfind(activecoin)) != 0 )
    {
        for (i=total=validated=0; i<coin->bundlescount; i++)
            if ( (bp= coin->bundles[i]) != 0 )
            {
                validated += iguana_bundlevalidate(coin,bp,1);
                total += bp->n;
            }
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"result","validation run");
        jaddstr(retjson,"coin",coin->symbol);
        jaddnum(retjson,"validated",validated);
        jaddnum(retjson,"total",total);
        jaddnum(retjson,"bundles",coin->bundlescount);
        jaddnum(retjson,"accuracy",(double)validated/total);
        return(jprint(retjson,1));
    } else return(clonestr("{\"error\":\"no active coin\"}"));
}

STRING_ARG(iguana,removecoin,activecoin)
{
    struct iguana_bundle *bp; int32_t i,height; char fname[1024];
    if ( (coin= iguana_coinfind(activecoin)) != 0 )
    {
        coin->active = 0;
        coin->started = 0;
        if ( 0 )
        {
            for (i=0; i<IGUANA_MAXPEERS; i++)
            {
                sprintf(fname,"%s/%s/vouts/%04d.vouts",GLOBAL_DBDIR,coin->symbol,i), OS_removefile(fname,0);
                sprintf(fname,"%s/%s/%04d.vins",coin->VALIDATEDIR,coin->symbol,i), OS_removefile(fname,0);
            }
            sprintf(fname,"%s/%s/vouts/*",GLOBAL_DBDIR,coin->symbol), OS_removefile(fname,0);
            sprintf(fname,"%s/%s/*",coin->VALIDATEDIR,coin->symbol), OS_removefile(fname,0);
            for (i=0; i<coin->bundlescount; i++)
            {
                sprintf(fname,"%s/%s/balancecrc.%d",GLOBAL_DBDIR,coin->symbol,i), OS_removefile(fname,0);
                if ( (bp= coin->bundles[i]) != 0 )
                {
                    iguana_bundlepurgefiles(coin,bp);
                    iguana_bundleremove(coin,bp->hdrsi,1);
                }
            }
            for (height=0; height<coin->longestchain; height+=IGUANA_SUBDIRDIVISOR)
            {
                sprintf(fname,"%s/%s/%d",GLOBAL_DBDIR,coin->symbol,height/IGUANA_SUBDIRDIVISOR);
                OS_remove_directory(fname);
            }
            sprintf(fname,"%s/%s/*",GLOBAL_DBDIR,coin->symbol), OS_remove_directory(fname);
        }
    }
    return(clonestr("{\"error\":\"no active coin\"}"));
}

INT_ARG(bitcoinrpc,getblockhash,height)
{
    cJSON *retjson = cJSON_CreateObject();
    jaddbits256(retjson,"result",iguana_blockhash(coin,height));
    return(jprint(retjson,1));
}

HASH_AND_TWOINTS(bitcoinrpc,getblock,blockhash,verbose,remoteonly)
{
    char *blockstr,*datastr; struct iguana_msgblock msg; struct iguana_block *block; cJSON *retjson; bits256 txid; int32_t len;
    retjson = cJSON_CreateObject();
    memset(&msg,0,sizeof(msg));
    if ( remoteonly == 0 && (block= iguana_blockfind("getblockRPC",coin,blockhash)) != 0 )
    {
        if ( verbose != 0 )
            return(jprint(iguana_blockjson(coin,block,1),1));
        else
        {
            if ( (len= iguana_peerblockrequest(coin,coin->blockspace,coin->blockspacesize,0,blockhash,0)) > 0 )
            {
                datastr = malloc(len*2 + 1);
                init_hexbytes_noT(datastr,coin->blockspace,len);
                jaddstr(retjson,"result",datastr);
                free(datastr);
                return(jprint(retjson,1));
            }
            jaddstr(retjson,"error","error getting rawblock");
        }
    }
    else if ( coin->APIblockstr != 0 )
        jaddstr(retjson,"error","already have pending request");
    else
    {
        memset(txid.bytes,0,sizeof(txid));
        if ( (blockstr= iguana_APIrequest(coin,blockhash,txid,5)) != 0 )
        {
            jaddstr(retjson,"result",blockstr);
            free(blockstr);
        } else jaddstr(retjson,"error","cant find blockhash");
    }
    return(jprint(retjson,1));
}

ZERO_ARGS(bitcoinrpc,getbestblockhash)
{
    cJSON *retjson = cJSON_CreateObject();
    char str[65]; jaddstr(retjson,"result",bits256_str(str,coin->blocks.hwmchain.RO.hash2));
    return(jprint(retjson,1));
}

ZERO_ARGS(bitcoinrpc,getblockcount)
{
    cJSON *retjson = cJSON_CreateObject();
    //printf("result %d\n",coin->blocks.hwmchain.height);
    jaddnum(retjson,"result",coin->blocks.hwmchain.height);
    return(jprint(retjson,1));
}

STRING_AND_INT(iguana,bundleaddresses,activecoin,height)
{
    struct iguana_info *ptr;
    if ( (ptr= iguana_coinfind(activecoin)) != 0 )
        return(iguana_bundleaddrs(ptr,height / coin->chain->bundlesize));
    else return(clonestr("{\"error\":\"activecoin is not active\"}"));
}

STRING_AND_INT(iguana,PoSweights,activecoin,height)
{
    struct iguana_info *ptr; int32_t num,nonz,errs,bundleheight; struct iguana_pkhash *refP; int64_t *weights,supply; cJSON *retjson;
    if ( (ptr= iguana_coinfind(activecoin)) != 0 )
    {
        //for (bundleheight=coin->chain->bundlesize; bundleheight<height; bundleheight+=coin->chain->bundlesize)
        {
            bundleheight = (height / ptr->chain->bundlesize) * ptr->chain->bundlesize;
            if ( (weights= iguana_PoS_weights(myinfo,ptr,&refP,&supply,&num,&nonz,&errs,bundleheight)) != 0 )
            {
                retjson = cJSON_CreateObject();
                jaddstr(retjson,"result",errs == 0 ? "success" : "error");
                jaddnum(retjson,"bundleheight",bundleheight);
                jaddnum(retjson,"numaddresses",num);
                jaddnum(retjson,"nonzero",nonz);
                jaddnum(retjson,"errors",errs);
                jaddnum(retjson,"supply",dstr(supply));
                free(weights);
                return(jprint(retjson,1));
            } else return(clonestr("{\"error\":\"iguana_PoS_weights returned null\"}"));
        }
    }
    return(clonestr("{\"error\":\"activecoin is not active\"}"));
}

STRING_ARG(iguana,stakers,activecoin)
{
    struct iguana_info *ptr; int32_t i,datalen,pkind,hdrsi; bits256 hash2; struct iguana_bundle *bp; cJSON *retjson,*array; struct iguana_pkhash *refP; struct iguana_ramchaindata *rdata; char coinaddr[64]; uint8_t refrmd160[20]; bits256 *sortbuf;
    if ( (ptr= iguana_coinfind(activecoin)) != 0 && ptr->RTheight > ptr->chain->bundlesize )
    {
        hdrsi = (ptr->RTheight / ptr->chain->bundlesize) - 1;
        if ( (bp= ptr->bundles[hdrsi]) != 0 && bp->weights != 0 && (rdata= bp->ramchain.H.data) != 0 && bp->weights != 0 )
        {
            sortbuf = calloc(bp->numweights,2 * sizeof(*sortbuf));
            for (i=datalen=0; i<bp->numweights; i++)
                datalen += iguana_rwnum(1,&((uint8_t *)sortbuf)[datalen],sizeof(bp->weights[i]),(void *)&bp->weights[i]);
            hash2 = bits256_doublesha256(0,(uint8_t *)sortbuf,datalen);
            refP = RAMCHAIN_PTR(rdata,Poffset);
            retjson = cJSON_CreateObject();
            array = cJSON_CreateArray();
            memset(refrmd160,0,sizeof(refrmd160));
            for (i=0; i<ptr->chain->bundlesize; i++)
            {
                if ( (pkind= iguana_staker_sort(ptr,&hash2,refrmd160,refP,bp->weights,bp->numweights,sortbuf)) > 0 )
                {
                    bitcoin_address(coinaddr,ptr->chain->pubtype,refP[pkind].rmd160,sizeof(refP[pkind].rmd160));
                    jaddistr(array,coinaddr);
                } else jaddistr(array,"error");
            }
            jaddstr(retjson,"result","success");
            jadd(retjson,"stakers",array);
            return(jprint(retjson,1));
        } else return(clonestr("{\"error\":\"iguana_stakers needs PoSweights and weights\"}"));
    }
    return(clonestr("{\"error\":\"activecoin is not active\"}"));
}

STRING_AND_INT(iguana,bundlehashes,activecoin,height)
{
    struct iguana_info *ptr; struct iguana_bundle *bp; int32_t i,hdrsi; cJSON *retjson,*array; struct iguana_ramchaindata *rdata;
    if ( (ptr= iguana_coinfind(activecoin)) != 0 )
    {
        hdrsi = height / coin->chain->bundlesize;
        if ( hdrsi < coin->bundlescount && hdrsi >= 0 && (bp= coin->bundles[hdrsi]) != 0 )
        {
            if ( (rdata= bp->ramchain.H.data) != 0 )
            {
                array = cJSON_CreateArray();
                for (i=0; i<IGUANA_NUMLHASHES; i++)
                    jaddinum(array,rdata->lhashes[i].txid);
                retjson = cJSON_CreateObject();
                jaddstr(retjson,"result","success");
                jaddbits256(retjson,"sha256",rdata->sha256);
                jadd(retjson,"bundlehashes",array);
                return(jprint(retjson,1));
            } else return(clonestr("{\"error\":\"ramchain not there\"}"));
        } else return(clonestr("{\"error\":\"height is too big\"}"));
    } else return(clonestr("{\"error\":\"activecoin is not active\"}"));
}

// low priority RPC

HASH_AND_TWOINTS(bitcoinrpc,listsinceblock,blockhash,target,flag)
{
    /*"transactions" : [
     {
     "account" : "doc test",
     "address" : "mmXgiR6KAhZCyQ8ndr2BCfEq1wNG2UnyG6",
     "category" : "receive",
     "amount" : 0.10000000,
     "vout" : 0,
     "confirmations" : 76478,
     "blockhash" : "000000000017c84015f254498c62a7c884a51ccd75d4dd6dbdcb6434aa3bd44d",
     "blockindex" : 1,
     "blocktime" : 1399294967,
     "txid" : "85a98fdf1529f7d5156483ad020a51b7f3340e47448cf932f470b72ff01a6821",
     "walletconflicts" : [
     ],
     "time" : 1399294967,
     "timereceived" : 1418924714
     },*/
    cJSON *retjson = cJSON_CreateObject();
    jaddstr(retjson,"error","low priority RPC not implemented");
    return(jprint(retjson,1));
}

ZERO_ARGS(bitcoinrpc,gettxoutsetinfo)
{
    cJSON *retjson = cJSON_CreateObject();
    jaddstr(retjson,"error","low priority RPC not implemented");
    return(jprint(retjson,1));
}

ZERO_ARGS(bitcoinrpc,listaddressgroupings)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    return(clonestr("{\"error\":\"low priority RPC not implemented\"}"));
}

SS_D_I_S(bitcoinrpc,move,fromaccount,toaccount,amount,minconf,comment)
{
    cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

#undef IGUANA_ARGS
#include "../includes/iguana_apiundefs.h"

