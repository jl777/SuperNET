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

#ifdef bitcoincancalculatebalances
int64_t bitcoin_value(struct iguana_info *coin,bits256 txid,int16_t vout,char *coinaddr)
{
    char params[512],str[65]; char *curlstr; cJSON *txobj,*vouts,*item,*sobj,*addrs; int32_t j,m,n; int64_t value = 0;
    sprintf(params,"[\"%s\", 1]",bits256_str(str,txid));
    if ( (curlstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"getrawtransaction",params)) != 0 )
    {
        if ( (txobj= cJSON_Parse(curlstr)) != 0 )
        {
            if ( (vouts= jarray(&n,txobj,"vout")) != 0 && vout < n )
            {
                item = jitem(vouts,vout);
                if ( (sobj= jobj(item,"scriptPubKey")) != 0 && (addrs= jarray(&m,sobj,"addresses")) != 0 )
                {
                    for (j=0; j<m; j++)
                    {
                        if ( strcmp(jstri(addrs,j),coinaddr) == 0 )
                        {
                            value = SATOSHIDEN * jdouble(item,"amount");
                            break;
                        }
                    }
                }
            }
            free_json(txobj);
        }
        free(curlstr);
    }
    return(value);
}

char *bitcoin_balance(struct iguana_info *coin,char *coinaddr,int32_t lastheight,int32_t minconf)
{
    int32_t i,n,height,maxconf=1<<30; int64_t balance = 0; char params[512],*curlstr; cJSON *array,*retjson,*curljson;
    retjson = cJSON_CreateObject();
    if ( (curlstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"getinfo",params)) != 0 )
    {
        if ( (curljson= cJSON_Parse(curlstr)) != 0 )
        {
            if ( (height= juint(curljson,"blocks")) > lastheight )
                maxconf = height - lastheight;
            free_json(curljson);
        }
        free(curlstr);
    }
    sprintf(params,"%d, %d, [\"%s\"]",minconf,maxconf,coinaddr);
    if ( (curlstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"listunspent",params)) != 0 )
    {
        if ( (array= cJSON_Parse(curlstr)) != 0 )
        {
            if ( (n= cJSON_GetArraySize(array)) > 0 )
            {
                for (i=0; i<n; i++)
                    balance += SATOSHIDEN * jdouble(jitem(array,i),"amount");
            }
            free_json(array);
        }
        free(curlstr);
    }
    jaddnum(retjson,"balance",dstr(balance));
    return(jprint(retjson,1));
}
#else

char *basilisk_bitcoinblockhashstr(char *coinstr,char *serverport,char *userpass,int32_t height)
{
    char numstr[128],*blockhashstr=0; 
    sprintf(numstr,"%d",height);
    blockhashstr = bitcoind_passthru(coinstr,serverport,userpass,"getblockhash",numstr);
    if ( blockhashstr == 0 || blockhashstr[0] == 0 )
    {
        printf("couldnt get blockhash for %u\n",height);
        if ( blockhashstr != 0 )
            free(blockhashstr);
        return(0);
    }
    return(blockhashstr);
}

int32_t basilisk_blockhashes(struct iguana_info *coin,int32_t height,int32_t n)
{
    char *blockhashstr; struct iguana_block *block,*checkblock; struct iguana_bundle *bp; int32_t bundlei,checki,h,i,num = 0; bits256 zero,hash2;
    h = height;
    for (i=0; i<n; i++,h++)
    {
        hash2 = iguana_blockhash(coin,h);
        if ( (block= iguana_blockfind("basilisk",coin,hash2)) != 0 && block->height == h && block->mainchain != 0 )
            continue;
        if ( (blockhashstr= basilisk_bitcoinblockhashstr(coin->symbol,coin->chain->serverport,coin->chain->userpass,h)) != 0 )
        {
            hash2 = bits256_conv(blockhashstr);
            memset(zero.bytes,0,sizeof(zero));
            if ( (bundlei= (h % coin->chain->bundlesize)) == 0 )
                bp = iguana_bundlecreate(coin,&checki,0,hash2,zero,1);
            block = iguana_blockhashset("remote",coin,h,hash2,1);
            iguana_bundlehash2add(coin,&checkblock,bp,bundlei,hash2);
            if ( block != checkblock || checki != bundlei )
                printf("block mismatch %p %p at ht.%d\n",block,checkblock,h);
            else block->mainchain = 1, num++;
            free(blockhashstr);
        }
    }
    return(num);
}

int32_t basilisk_blockheight(struct iguana_info *coin,bits256 hash2)
{
    char buf[128],str[65],*blocktxt; cJSON *blockjson; int32_t height=-1;
    sprintf(buf,"\"%s\"",bits256_str(str,hash2));
    if ( (blocktxt= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"getblock",buf)) != 0 )
    {
        if ( (blockjson= cJSON_Parse(blocktxt)) != 0 )
        {
            height = jint(blockjson,"height");
            free_json(blockjson);
        }
        free(blocktxt);
    }
    return(height);
}

/*bits256 basilisk_blockhash(struct iguana_info *coin,bits256 prevhash2)
{
    char *blockhashstr; bits256 hash2; int32_t height;
    memset(hash2.bytes,0,sizeof(hash2));
    if ( (height= basilisk_blockheight(coin,prevhash2)) >= 0 )
    {
        printf("blockhash.%d\n",height);
        if ( (blockhashstr= bitcoin_blockhashstr(coin->symbol,coin->chain->serverport,coin->chain->userpass,height+1)) != 0 )
        {
            printf("got (%s)\n",blockhashstr);
            hash2 = bits256_conv(blockhashstr);
            free(blockhashstr);
        }
    }
    return(hash2);
}*/

cJSON *bitcoin_blockjson(int32_t *heightp,char *coinstr,char *serverport,char *userpass,char *blockhashstr,int32_t height)
{
    cJSON *json = 0; int32_t flag = 0; char buf[1024],*blocktxt = 0;
    if ( blockhashstr == 0 )
        blockhashstr = basilisk_bitcoinblockhashstr(coinstr,serverport,userpass,height), flag = 1;
    if ( blockhashstr != 0 )
    {
        sprintf(buf,"\"%s\"",blockhashstr);
        blocktxt = bitcoind_passthru(coinstr,serverport,userpass,"getblock",buf);
        //printf("get_blockjson.(%d %s) %s\n",height,blockhashstr,blocktxt);
        if ( blocktxt != 0 && blocktxt[0] != 0 && (json= cJSON_Parse(blocktxt)) != 0 && heightp != 0 )
            if ( (*heightp= juint(json,"height")) != height )
                *heightp = -1;
        if ( flag != 0 && blockhashstr != 0 )
            free(blockhashstr);
        if ( blocktxt != 0 )
            free(blocktxt);
    }
    return(json);
}

int32_t basilisk_bitcoinscan(struct iguana_info *coin,uint8_t origblockspace[IGUANA_MAXPACKETSIZE],struct OS_memspace *rawmem)
{
    struct iguana_txblock txdata; int32_t len,starti,h,num=0,loadheight,hexlen,datalen,n,i,numtxids,flag=0,j,height=-1; cJSON *curljson,*blockjson,*txids; char *bitstr,*curlstr,params[128],str[65]; struct iguana_msghdr H; struct iguana_msgblock *msg; uint8_t *blockspace,revbits[4],bitsbuf[4];
    strcpy(params,"[]");
    if ( (curlstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"getinfo",params)) != 0 )
    {
        if ( (curljson= cJSON_Parse(curlstr)) != 0 )
        {
            height = juint(curljson,"blocks");
            free_json(curljson);
        }
        free(curlstr);
    }
    loadheight = coin->blocks.hwmchain.height;
    if ( loadheight == 0 )
        loadheight = 1;
    basilisk_blockhashes(coin,loadheight,coin->chain->bundlesize);
    for (j=0; j<coin->chain->bundlesize; j++)
    {
        flag = 0;
        if ( (blockjson= bitcoin_blockjson(&h,coin->symbol,coin->chain->serverport,coin->chain->userpass,0,loadheight)) != 0 )
        {
            blockspace = origblockspace;
            msg = (void *)blockspace;
            memset(msg,0,sizeof(*msg));
            msg->H.version = juint(blockjson,"version");
            msg->H.prev_block = jbits256(blockjson,"previousblockhash");
            msg->H.merkle_root = jbits256(blockjson,"merkleroot");
            msg->H.timestamp = juint(blockjson,"timestamp");
            if ( (bitstr= jstr(blockjson,"bits")) != 0 )
            {
                decode_hex(revbits,sizeof(revbits),bitstr);
                for (i=0; i<4; i++)
                    bitsbuf[i] = revbits[3 - i];
                memcpy(&msg->H.bits,bitsbuf,sizeof(msg->H.bits));
            }
            msg->H.nonce = juint(blockjson,"nonce");
            datalen = 80;
            if ( (txids= jarray(&numtxids,blockjson,"tx")) != 0 )
            {
                msg->txn_count = numtxids;
                if ( numtxids < 0xfd )
                    blockspace[datalen++] = numtxids;
                else
                {
                    blockspace[datalen++] = 0xfd;
                    blockspace[datalen++] = numtxids & 0xff;
                    blockspace[datalen++] = numtxids >> 8;
                }
                starti = datalen;
                for (i=0; i<numtxids; i++)
                {
                    sprintf(params,"[\"%s\"]",bits256_str(str,jbits256(jitem(txids,i),0)));
                    if ( (curlstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"getrawtransaction",params)) != 0 )
                    {
                        //printf("%s txid.%d\n",curlstr,i);
                        if ( (hexlen= is_hexstr(curlstr,0)) > 1 )
                        {
                            hexlen >>= 1;
                            decode_hex(&blockspace[datalen],hexlen,curlstr);
                            datalen += hexlen;
                        }
                        free(curlstr);
                    }
                }
                num++;
                coin->blocks.pending++;
                if ( rawmem->ptr == 0 )
                    iguana_meminit(rawmem,"basilisk",0,IGUANA_MAXPACKETSIZE*3,0);
                else iguana_memreset(rawmem);
                memset(&txdata,0,sizeof(txdata));
                memset(&H,0,sizeof(H));
                if ( (n= iguana_gentxarray(coin,rawmem,&txdata,&len,blockspace,datalen)) == datalen )
                {
                    len = n;
                    iguana_gotblockM(coin,0,&txdata,rawmem->ptr,&H,blockspace,datalen);
                    flag = 1;
                    //if ( (rand() % 1000) == 0 )
                        printf("%s height.%-7d datalen.%-6d | HWM.%d\n",coin->symbol,h,datalen,coin->blocks.hwmchain.height);
                }
                else
                {
                    printf(" parse error block.%d txn_count.%d, n.%d len.%d vs datalen.%d\n",loadheight,txdata.block.RO.txn_count,n,len,datalen);
                }
            }
            free_json(blockjson);
        }
        loadheight++;
        if ( flag == 0 )
            break;
    }
    if ( coin->blocks.pending > 0 )
        coin->blocks.pending--;
    return(num);
}

#endif

int32_t basilisk_bitcoinavail(struct iguana_info *coin)
{
    if ( coin->VALIDATENODE != 0 || coin->RELAYNODE != 0 )
        return(1);
    //else if ( coin->chain->serverport[0] != 0 )
    //    return(1);
    else return(0);
}

int64_t basilisk_bitcoinbalances(struct supernet_info *myinfo,struct iguana_info *coin,char *remoteaddr,uint32_t basilisktag,cJSON **arrayp,int32_t lastheight,int32_t minconf,cJSON *addresses,int32_t timeoutmillis)
{
    cJSON *array=0,*result,*item,*retjson,*hexjson; int32_t i,n,besti=-1; char *coinaddr,*balancestr=0,*retstr=0; int64_t total=0,amount,most=0; struct basilisk_item *ptr;
    array = cJSON_CreateArray();
    if ( coin != 0 && basilisk_bitcoinavail(coin) != 0 )
    {
        if ( (n= cJSON_GetArraySize(addresses)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                coinaddr = jstri(addresses,i);
                if ( coin->VALIDATENODE != 0 || coin->RELAYNODE != 0 )
                    balancestr = iguana_balance(myinfo,coin,0,remoteaddr,coin->symbol,coinaddr,lastheight,minconf);
                //else balancestr = bitcoin_balance(coin,coinaddr,lastheight,minconf);
                if ( balancestr != 0 )
                {
                    if ( (result= cJSON_Parse(balancestr)) != 0 )
                    {
                        if ( jobj(result,"balance") != 0 )
                        {
                            item = cJSON_CreateObject();
                            amount = SATOSHIDEN * jdouble(result,"balance");
                            total += amount;
                            jaddnum(item,coinaddr,dstr(amount));
                            jaddi(array,item);
                        }
                        free_json(result);
                    }
                    free(balancestr);
                }
            }
        }
    }
    else
    {
        hexjson = cJSON_CreateObject();
        jaddnum(hexjson,"basilisktag",basilisktag);
        jadd(hexjson,"addresses",jduplicate(addresses));
        jaddnum(hexjson,"minconf",minconf);
        jaddnum(hexjson,"lastheight",lastheight);
        jaddstr(hexjson,"agent","basilisk");
        jaddstr(hexjson,"method","balances");
        if ( (ptr= basilisk_issue(myinfo,hexjson,timeoutmillis,0,1,basilisktag)) != 0 )
        {
            for (i=0; i<ptr->numresults; i++)
            {
                if ( ptr->results[i] == 0 )
                    continue;
                if ( retstr != 0 && strcmp(ptr->results[i],retstr) == 0 )
                    ptr->numexact++;
                if ( (retjson= cJSON_Parse(ptr->results[i])) != 0 )
                {
                    if ( (total= j64bits(retjson,"balance")) > most )
                    {
                        most = total;
                        besti = i;
                    }
                    free_json(retjson);
                }
            }
            retstr = basilisk_finish(ptr,arrayp,besti);
        }
        free_json(hexjson);
    }
    *arrayp = array;
    return(most);
}

int64_t basilisk_bitcoinvalue(struct supernet_info *myinfo,struct iguana_info *coin,char *remoteaddr,uint32_t basilisktag,bits256 txid,int32_t vout,char *coinaddr,int32_t timeoutmillis)
{
    int32_t i,height; struct basilisk_value *v; cJSON *hexjson; uint64_t value = 0; struct basilisk_item *ptr;
    if ( coin != 0 && basilisk_bitcoinavail(coin) != 0 )
    {
        if ( coin->VALIDATENODE != 0 || coin->RELAYNODE != 0 )
        {
            if ( iguana_unspentindfind(coin,coinaddr,0,0,&value,&height,txid,vout,coin->bundlescount) > 0 )
                return(value);
        } //else return(bitcoin_value(coin,txid,vout,coinaddr));
    }
    else
    {
        if ( (v= myinfo->basilisks.values) != 0 )
        {
            for (i=0; i<myinfo->basilisks.numvalues; i++,v++)
            {
                if ( v->vout == vout && bits256_cmp(txid,v->txid) == 0 && strcmp(v->coinaddr,coinaddr) == 0 )
                    return(v->value);
            }
        }
        hexjson = cJSON_CreateObject();
        jaddnum(hexjson,"basilisktag",basilisktag);
        jaddstr(hexjson,"address",coinaddr);
        jaddbits256(hexjson,"txid",txid);
        jaddnum(hexjson,"vout",vout);
        jaddstr(hexjson,"agent","basilisk");
        jaddstr(hexjson,"method","value");
        if ( (ptr= basilisk_issue(myinfo,hexjson,timeoutmillis,0,1,basilisktag)) != 0 )
        {
            v = &myinfo->basilisks.values[myinfo->basilisks.numvalues++];
            strcpy(v->coinaddr,coinaddr);
            v->value = value;
            v->txid = txid;
        }
        free_json(hexjson);
    }
    return(value);
}

int64_t basilisk_bitcointxcost(struct supernet_info *myinfo,struct iguana_info *coin,char *remoteaddr,uint32_t locktime,int64_t satoshis,int64_t txfee,cJSON *addresses,char *spendscriptstr,char *changeaddr,char *rawtx,cJSON *vins)
{
    cJSON *txobj,*vouts,*vin,*sobj,*addrs; int64_t change=0,outputsum=0,inputsum=0,spentsatoshis=0,cost = -1; int32_t i,j,m,numaddrs,spendlen,n; struct iguana_msgtx msgtx; uint8_t extraspace[8192],script[IGUANA_MAXSCRIPTSIZE],asmtype; struct vin_info V; char *scriptstr,str[65]; bits256 txid;
    if ( coin != 0 )
    {
        spendlen = (int32_t)strlen(spendscriptstr) >> 1;
        decode_hex(script,spendlen,spendscriptstr);
        if ( (txobj= bitcoin_hex2json(coin,&txid,&msgtx,rawtx,extraspace,sizeof(extraspace))) != 0 )
        {
            if ( juint(txobj,"locktime") != locktime )
            {
                printf("locktime mismatch %u != %u\n",juint(txobj,"locktime"),locktime);
                return(-1);
            }
            else if ( jobj(txobj,"error") == 0 && (vins= jarray(&n,txobj,"vin")) != 0 && cJSON_GetArraySize(vins) == msgtx.tx_in )
            {
                numaddrs = cJSON_GetArraySize(addresses);
                for (i=0; i<msgtx.tx_in; i++)
                {
                    vin = jitem(vins,i);
                    if ( (sobj= jobj(vin,"scriptPubKey")) != 0 && (scriptstr= jstr(sobj,"hex")) != 0 )
                    {
                        memset(&V,0,sizeof(V));
                        V.spendlen = (int32_t)strlen(scriptstr) >> 1;
                        decode_hex(V.spendscript,V.spendlen,scriptstr);
                        asmtype = _iguana_calcrmd160(coin,&V);
                        if ( basilisk_bitcoinvalue(myinfo,coin,remoteaddr,0,msgtx.vins[i].prev_hash,msgtx.vins[i].prev_vout,V.coinaddr,10000) == V.amount )
                        {
                            inputsum += V.amount;
                            for (j=0; j<numaddrs; j++)
                                if ( strcmp(jstri(addresses,j),V.coinaddr) == 0 )
                                    break;
                            if ( j == numaddrs )
                            {
                                printf("spend of invalid input address.(%s)\n",V.coinaddr);
                                free_json(txobj);
                                return(-1);
                            }
                        }
                        else
                        {
                            printf("spend of invalid %s unspent.(%s).%d\n",V.coinaddr,bits256_str(str,msgtx.vins[i].prev_hash),msgtx.vins[i].prev_vout);
                            free_json(txobj);
                            return(-1);
                        }
                    }
                }
                if ( (vouts= jarray(&n,txobj,"vout")) != 0 && n == msgtx.tx_out )
                {
                    for (i=0; i<msgtx.tx_out; i++)
                    {
                        outputsum += msgtx.vouts[i].value;
                        if ( spendlen == msgtx.vouts[i].pk_scriptlen && memcmp(script,msgtx.vouts[i].pk_script,spendlen) == 0 )
                        {
                            spentsatoshis = msgtx.vouts[i].value;
                            continue;
                        }
                        else
                        {
                            if ( (sobj= jobj(jitem(vouts,i),"scriptPubKey")) != 0 && (addrs= jarray(&m,sobj,"addresses")) != 0 )
                            {
                                if ( m == 1 && strcmp(jstri(addrs,0),changeaddr) == 0 )
                                {
                                    change = msgtx.vouts[i].value;
                                    printf("verify it is normal spend for %s\n",changeaddr);
                                    continue;
                                }
                            }
                        }
                        cost += msgtx.vouts[i].value;
                    }
                }
            }
            free_json(txobj);
        }
    }
    if ( spentsatoshis != satoshis )
    {
        printf("spentsatoshis %.8f != expected %.8f, change %.8f\n",dstr(spentsatoshis),dstr(satoshis),dstr(change));
        return(-1);
    }
    if ( (inputsum - outputsum) != txfee )
    {
        printf("inputsum %.8f - outputsum %.8f = %.8f != txfee %.8f\n",dstr(inputsum),dstr(outputsum),dstr(inputsum)-dstr(outputsum),dstr(txfee));
        return(-1);
    }
    return(cost);
}

char *basilisk_bitcoinrawtx(struct supernet_info *myinfo,struct iguana_info *coin,char *remoteaddr,uint32_t basilisktag,cJSON **vinsp,uint32_t locktime,uint64_t satoshis,char *changeaddr,uint64_t txfee,cJSON *addresses,int32_t minconf,char *spendscriptstr,int32_t timeoutmillis)
{
    uint8_t buf[IGUANA_MAXSCRIPTSIZE]; int32_t i,spendlen,besti=-1; cJSON *hexjson,*valsobj,*txobj = 0; char *retstr=0,*rawtx = 0; int64_t cost,bestcost=-1; struct basilisk_item *ptr;
    *vinsp = 0;
    if ( coin != 0 && basilisk_bitcoinavail(coin) != 0 )
    {
        if ( coin->VALIDATENODE != 0 || coin->RELAYNODE != 0 )
        {
            if ( txfee == 0 )
                txfee = coin->chain->txfee;
            if ( (txobj= bitcoin_txcreate(coin,locktime)) != 0 )
            {
                spendlen = (int32_t)strlen(spendscriptstr) >> 1;
                decode_hex(buf,spendlen,spendscriptstr);
                bitcoin_txoutput(coin,txobj,buf,spendlen,satoshis);
                rawtx = iguana_calcrawtx(myinfo,coin,vinsp,txobj,satoshis,changeaddr,txfee,addresses,minconf);
            } else printf("error creating txobj\n");
        } //else rawtx = bitcoin_calcrawtx(myinfo,coin,vinsp,satoshis,spendscriptstr,changeaddr,txfee,addresses,minconf,locktime);
        if ( rawtx != 0 )
        {
            if ( *vinsp != 0 )
            {
                free_json(txobj);
                //printf("return locally generated rawtx.(%s) vins.%p\n",rawtx,*vinsp);
                return(rawtx);
            } else free(rawtx);
        }
    }
    if ( txobj != 0 )
        free_json(txobj);
    if ( addresses != 0 )
    {
        valsobj = cJSON_CreateObject();
        jaddnum(valsobj,"basilisktag",basilisktag);
        jaddstr(valsobj,"coin",coin->symbol);
        jadd64bits(valsobj,"amount",satoshis);
        jadd64bits(valsobj,"txfee",txfee);
        jaddnum(valsobj,"minconf",minconf);
        jaddnum(valsobj,"locktime",locktime);
        hexjson = cJSON_CreateObject();
        jaddstr(hexjson,"changeaddr",changeaddr);
        jaddstr(hexjson,"spendscriptstr",spendscriptstr);
        jadd(hexjson,"addresses",jduplicate(addresses));
        jadd(hexjson,"vals",valsobj);
        jaddstr(hexjson,"agent","basilisk");
        jaddstr(hexjson,"method","rawtx");
        if ( (ptr= basilisk_issue(myinfo,hexjson,timeoutmillis,0,1,basilisktag)) != 0 )
        {
            for (i=0; i<ptr->numresults; i++)
            {
                if ( ptr->results[i] == 0 )
                    continue;
                if ( retstr != 0 && strcmp(ptr->results[i],retstr) == 0 )
                    ptr->numexact++;
                if ( (cost= basilisk_bitcointxcost(myinfo,coin,remoteaddr,locktime,satoshis,txfee,addresses,spendscriptstr,changeaddr,ptr->results[i],ptr->resultargs[i])) >= 0 && (bestcost == 0 || cost < bestcost) )
                {
                    if ( retstr != 0 )
                        ptr->numexact = 0;
                    retstr = ptr->results[i];
                    bestcost = cost;
                    besti = i;
                }
            }
            retstr = basilisk_finish(ptr,vinsp,besti);
        }
        free_json(hexjson);
    }
    return(retstr);
}
