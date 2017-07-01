
/******************************************************************************
 * Copyright © 2014-2017 The SuperNET Developers.                             *
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
//
//  LP_scan.c
//  marketmaker
//

uint64_t oldLP_txvalue(char *symbol,bits256 txid,int32_t vout)
{
    uint64_t value = 0; double interest; cJSON *txobj,*vouts,*utxoobj; int32_t numvouts;
    if ( (txobj= LP_gettx(symbol,txid)) != 0 )
    {
        //char str[65]; printf("%s.(%s) txobj.(%s)\n",symbol,bits256_str(str,txid),jprint(txobj,0));
        if ( (vouts= jarray(&numvouts,txobj,"vout")) != 0 && vout < numvouts )
        {
            utxoobj = jitem(vouts,vout);
            if ( (value= jdouble(utxoobj,"amount")*SATOSHIDEN) == 0 && (value= jdouble(utxoobj,"value")*SATOSHIDEN) == 0 )
            {
                char str[65]; printf("%s LP_txvalue.%s strange utxo.(%s) vout.%d/%d\n",symbol,bits256_str(str,txid),jprint(utxoobj,0),vout,numvouts);
            }
            else if ( strcmp(symbol,"KMD") == 0 )
            {
                if ( (utxoobj= LP_gettxout(symbol,txid,vout)) != 0 )
                {
                    if ( (interest= jdouble(utxoobj,"interest")) != 0. )
                    {
                        //printf("add interest of %.8f to %.8f\n",interest,dstr(value));
                        value += SATOSHIDEN * interest;
                    }
                    free_json(utxoobj);
                }
            }
        }
        free_json(txobj);
    }
    return(value);
}

uint64_t LP_txvalue(char *coinaddr,char *symbol,bits256 txid,int32_t vout)
{
    uint64_t value = 0; double interest; cJSON *txobj,*sobj,*array; int32_t n;
    coinaddr[0] = 0;
    if ( (txobj= LP_gettxout(symbol,txid,vout)) != 0 )
    {
        if ( (value= jdouble(txobj,"amount")*SATOSHIDEN) == 0 && (value= jdouble(txobj,"value")*SATOSHIDEN) == 0 )
        {
            char str[65]; printf("%s LP_txvalue.%s strange utxo.(%s) vout.%d\n",symbol,bits256_str(str,txid),jprint(txobj,0),vout);
        }
        else if ( strcmp(symbol,"KMD") == 0 )
        {
            if ( (interest= jdouble(txobj,"interest")) != 0. )
            {
                //printf("add interest of %.8f to %.8f\n",interest,dstr(value));
                value += SATOSHIDEN * interest;
            }
        }
        if ( (sobj= jobj(txobj,"scriptPubKey")) != 0 && (array= jarray(&n,sobj,"addresses")) != 0 )
            strcpy(coinaddr,jstri(array,0));
        //char str[65]; printf("%.8f <- %s.(%s) txobj.(%s)\n",dstr(value),symbol,bits256_str(str,txid),jprint(txobj,0));
        free_json(txobj);
    }
    return(value);
}

int32_t LP_vinscan(bits256 *spendtxidp,int32_t *spendvinip,char *symbol,bits256 txid,bits256 searchtxid,int32_t searchvout,bits256 searchtxid2,int32_t searchvout2)
{
    cJSON *txobj,*vins,*vin; bits256 spenttxid; int32_t j,numvins,spentvout,retval = -1;
    if ( (txobj= LP_gettx(symbol,txid)) != 0 )
    {
        if ( bits256_cmp(txid,jbits256(txobj,"txid")) != 0 )
        {
            char str[65]; printf("txid mismatch error %s vs %s\n",bits256_str(str,txid),jprint(txobj,0));
            free_json(txobj);
            return(-2);
        }
        vins = jarray(&numvins,txobj,"vin");
        for (j=0; j<numvins; j++)
        {
            vin = jitem(vins,j);
            spenttxid = jbits256(vin,"txid");
            spentvout = jint(vin,"vout");
            if ( spentvout == searchvout && bits256_cmp(spenttxid,searchtxid) == 0 )
            {
                *spendtxidp = txid;
                *spendvinip = j;
                retval = 0;
                break;
            }
            else if ( spentvout == searchvout2 && bits256_cmp(spenttxid,searchtxid2) == 0 )
            {
                *spendtxidp = txid;
                *spendvinip = j;
                retval = 1;
                break;
            }
        }
        free_json(txobj);
    } else printf("unexpected missing txid\n"), retval = -3;
    return(retval);
}

int32_t LP_spendsearch(bits256 *spendtxidp,int32_t *indp,char *symbol,bits256 searchtxid,int32_t searchvout)
{
    char destaddr[64]; cJSON *blockjson,*txids,*txobj; bits256 hash,txid; int32_t h,i,j,numtxids,loadheight,errs = 0;
    *indp = -1;
    memset(spendtxidp,0,sizeof(*spendtxidp));
    if ( LP_txvalue(destaddr,symbol,searchtxid,searchvout) > 0 )
        return(0);
    if ( (txobj= LP_gettx(symbol,searchtxid)) == 0 )
        return(0);
    hash = jbits256(txobj,"blockhash");
    free_json(txobj);
    if ( bits256_nonz(hash) == 0 )
        return(0);
    if ( (blockjson= LP_getblock(symbol,hash)) == 0 )
        return(0);
    loadheight = jint(blockjson,"height");
    free_json(blockjson);
    if ( loadheight <= 0 )
        return(0);
    while ( errs == 0 && *indp < 0 )
    {
        //printf("search %s ht.%d\n",symbol,loadheight);
        if ( (blockjson= LP_blockjson(&h,symbol,0,loadheight)) != 0 && h == loadheight )
        {
            if ( (txids= jarray(&numtxids,blockjson,"tx")) != 0 )
            {
                for (i=0; i<numtxids; i++)
                {
                    txid = jbits256(jitem(txids,i),0);
                    if ( (j= LP_vinscan(spendtxidp,indp,symbol,txid,searchtxid,searchvout,searchtxid,searchvout)) >= 0 )
                        break;
                }
            }
            free_json(blockjson);
        } else errs++;
        loadheight++;
    }
    char str[65]; printf("reached %s ht.%d %s/v%d\n",symbol,loadheight,bits256_str(str,*spendtxidp),*indp);
    if ( bits256_nonz(*spendtxidp) != 0 && *indp >= 0 )
        return(loadheight);
    else return(0);
}

int32_t LP_mempoolscan(char *symbol,bits256 txid)
{
    int32_t i,n; cJSON *array;
    if ( (array= LP_getmempool(symbol)) != 0 )
    {
        if ( is_cJSON_Array(array) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
        {
            for (i=0; i<n; i++)
                if ( bits256_cmp(txid,jbits256i(array,i)) == 0 )
                {
                    char str[65]; printf("found %s tx.(%s) in mempool slot.%d\n",symbol,bits256_str(str,txid),i);
                    return(i);
                }
        }
        free_json(array);
    }
    return(-1);
}

int32_t LP_numconfirms(struct basilisk_swap *swap,struct basilisk_rawtx *rawtx)
{
    int32_t numconfirms = 100;
//#ifndef BASILISK_DISABLEWAITTX
    cJSON *txobj;
    numconfirms = -1;
    if ( (txobj= LP_gettx(rawtx->coin->symbol,rawtx->I.signedtxid)) != 0 )
    {
        numconfirms = jint(txobj,"confirmations");
        free_json(txobj);
    }
    else if ( LP_mempoolscan(rawtx->coin->symbol,rawtx->I.signedtxid) >= 0 )
        numconfirms = 0;
//#endif
    return(numconfirms);
}

int32_t LP_waitmempool(char *symbol,bits256 txid,int32_t duration)
{
    uint32_t expiration = (uint32_t)time(NULL) + duration;
    while ( time(NULL) < expiration )
    {
        if ( LP_mempoolscan(symbol,txid) >= 0 )
            return(0);
        usleep(250000);
    }
    return(-1);
}

int32_t LP_mempool_vinscan(bits256 *spendtxidp,int32_t *spendvinp,char *symbol,bits256 searchtxid,int32_t searchvout,bits256 searchtxid2,int32_t searchvout2)
{
    int32_t i,n; cJSON *array; bits256 mempooltxid;
    if ( symbol == 0 || symbol[0] == 0 || bits256_nonz(searchtxid) == 0 || bits256_nonz(searchtxid2) == 0 )
        return(-1);
    if ( (array= LP_getmempool(symbol)) != 0 )
    {
        if ( is_cJSON_Array(array) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                mempooltxid = jbits256i(array,i);
                if ( (*spendvinp= LP_vinscan(spendtxidp,spendvinp,symbol,mempooltxid,searchtxid,searchvout,searchtxid2,searchvout2)) >= 0 )
                    return(i);
            }
            free_json(array);
        }
    }
    return(-1);
}


