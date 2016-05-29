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

struct bitcoin_rawtxdependents
{
    int64_t spentsatoshis,outputsum,cost,change;
    int32_t numptrs,numresults;
    char **results,*coinaddrs;
    struct basilisk_item *ptrs[];
};

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

char *basilisk_bitcoinblockhashstr(char *coinstr,char *serverport,char *userpass,int32_t height)
{
    char numstr[128],*blockhashstr=0; bits256 hash2; struct iguana_info *coin;
    sprintf(numstr,"%d",height);
    if ( (blockhashstr= bitcoind_passthru(coinstr,serverport,userpass,"getblockhash",numstr)) == 0 )
        return(0);
    hash2 = bits256_conv(blockhashstr);
    if ( blockhashstr == 0 || blockhashstr[0] == 0 || bits256_nonz(hash2) == 0 )
    {
        printf("couldnt get blockhash for %u, probably curl is disabled\n",height);
        if ( blockhashstr != 0 )
            free(blockhashstr);
        if ( height == 0 )
        {
            if ( (coin= iguana_coinfind(coinstr)) != 0 )
            {
                bits256_str(numstr,*(bits256 *)coin->chain->genesis_hashdata);
                return(clonestr(numstr));
            }
        }
        return(0);
    }
    return(blockhashstr);
}

int32_t basilisk_blockhashes(struct iguana_info *coin,int32_t height,int32_t n)
{
    char *blockhashstr; struct iguana_block *block,*checkblock; struct iguana_bundle *bp=0; int32_t bundlei,checki,h,i,num = 0; bits256 zero,hash2;
    h = height;
    for (i=0; i<n; i++,h++)
    {
        hash2 = iguana_blockhash(coin,h);
        if ( 0 && (block= iguana_blockfind("basilisk",coin,hash2)) != 0 && block->height == h && block->mainchain != 0 )
            continue;
        if ( (blockhashstr= basilisk_bitcoinblockhashstr(coin->symbol,coin->chain->serverport,coin->chain->userpass,h)) != 0 && bits256_nonz(hash2) != 0 )
        {
            hash2 = bits256_conv(blockhashstr);
            memset(zero.bytes,0,sizeof(zero));
            block = iguana_blockhashset("remote",coin,h,hash2,1);
            if ( (bundlei= (h % coin->chain->bundlesize)) == 0 )
                bp = iguana_bundlecreate(coin,&checki,h,hash2,zero,1);
            iguana_bundlehash2add(coin,&checkblock,bp,bundlei,hash2);
            if ( block != checkblock )
                printf("bp.%p block mismatch %p %p at ht.%d bundlei.%d\n",bp,block,checkblock,h,bundlei);
            else
            {
                block->mainchain = 1;
                char str[65]; printf("%s ht.%d\n",bits256_str(str,hash2),h);
                num++;
            }
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
    struct iguana_txblock txdata; struct iguana_block B; int32_t len,starti,h,num=0,loadheight,hexlen,datalen,n,i,numtxids,flag=0,j,height=-1; cJSON *curljson,*blockjson,*txids; char *bitstr,*curlstr,params[128],str[65]; struct iguana_msghdr H; struct iguana_msgblock *msg; uint8_t *blockspace,revbits[4],bitsbuf[4]; bits256 hash2,checkhash2;
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
    basilisk_blockhashes(coin,loadheight,coin->chain->bundlesize);
    for (j=0; j<coin->chain->bundlesize; j++)
    {
        if ( loadheight == 0 )
        {
            loadheight++;
            continue;
        }
        basilisk_blockhashes(coin,loadheight,1);
        flag = 0;
        if ( (blockjson= bitcoin_blockjson(&h,coin->symbol,coin->chain->serverport,coin->chain->userpass,0,loadheight)) != 0 )
        {
            blockspace = origblockspace;
            memset(&B,0,sizeof(B));
            B.RO.version = juint(blockjson,"version");
            B.RO.prev_block = jbits256(blockjson,"previousblockhash");
            B.RO.merkle_root = jbits256(blockjson,"merkleroot");
            B.RO.timestamp = juint(blockjson,"time");
            if ( (bitstr= jstr(blockjson,"bits")) != 0 )
            {
                decode_hex(revbits,sizeof(uint32_t),bitstr);
                for (i=0; i<4; i++)
                    bitsbuf[i] = revbits[3 - i];
                memcpy(&B.RO.bits,bitsbuf,sizeof(B.RO.bits));
            }
            B.RO.nonce = juint(blockjson,"nonce");
            //char str[65],str2[65];
            //printf("v.%d t.%u bits.%08x nonce.%x %s %s\n",B.RO.version,B.RO.timestamp,B.RO.bits,B.RO.nonce,bits256_str(str,B.RO.prev_block),bits256_str(str2,B.RO.merkle_root));
            iguana_serialize_block(coin->chain,&checkhash2,blockspace,&B);
            //for (i=0; i<80; i++)
            //    printf("%02x",blockspace[i]);
            //printf(" B.%s\n",bits256_str(str,checkhash2));
            msg = (void *)blockspace;
            //printf("(%s)\n",jprint(blockjson,0));
            checkhash2 = iguana_calcblockhash(coin->symbol,coin->chain->hashalgo,blockspace,sizeof(*msg)-4);
            if ( jstr(blockjson,"hash") != 0 )
                hash2 = bits256_conv(jstr(blockjson,"hash"));
            else memset(hash2.bytes,0,sizeof(hash2));
            //printf("%s vs %s %ld\n",bits256_str(str,hash2),bits256_str(str2,checkhash2),sizeof(*msg)-4);
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
                        printf("%s h.%-7d len.%-6d | HWM.%d\n",coin->symbol,h,datalen,coin->blocks.hwmchain.height);
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

void *basilisk_bitcoinbalances(struct basilisk_item *Lptr,struct supernet_info *myinfo,struct iguana_info *coin,char *remoteaddr,uint32_t basilisktag,int32_t timeoutmillis,cJSON *vals)
{
   /* cJSON *array=0,*result,*item,*retjson,*hexjson; int32_t i,n,besti=-1; char *coinaddr,*balancestr=0,*retstr=0; int64_t total=0,amount,most=0; struct basilisk_item *ptr;
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
    return(most);*/
    return(0);
}

char *basilisk_valuestr(struct iguana_info *coin,char *coinaddr,uint64_t value,int32_t height,bits256 txid,int16_t vout)
{
    cJSON *retjson = cJSON_CreateObject();
    jaddnum(retjson,"result",dstr(value));
    jaddstr(retjson,"address",coinaddr);
    jadd64bits(retjson,"value",value);
    jaddnum(retjson,"height",height);
    jaddbits256(retjson,"txid",txid);
    jaddnum(retjson,"vout",vout);
    return(jprint(retjson,1));
}

double basilisk_bitcoin_valuemetric(struct supernet_info *myinfo,struct basilisk_item *ptr,char *resultstr)
{
    struct basilisk_value *v; cJSON *resultarg; int32_t ind;
    if ( (ind= myinfo->basilisks.numvalues) >= sizeof(myinfo->basilisks.values)/sizeof(*myinfo->basilisks.values) )
        ind = (rand() % (sizeof(myinfo->basilisks.values)/sizeof(*myinfo->basilisks.values)));
    else myinfo->basilisks.numvalues++;
    v = &myinfo->basilisks.values[ind];
    if ( (resultarg= cJSON_Parse(resultstr)) != 0 )
    {
        safecopy(v->coinaddr,jstr(resultarg,"address"),sizeof(v->coinaddr));
        v->value = j64bits(resultarg,"value");
        v->txid = jbits256(resultarg,"txid");
        v->vout = jint(resultarg,"vout");
        v->height = jint(resultarg,"height");
    }
    return(ind + 1);
}

void *basilisk_bitcoinvalue(struct basilisk_item *Lptr,struct supernet_info *myinfo,struct iguana_info *coin,char *remoteaddr,uint32_t basilisktag,int32_t timeoutmillis,cJSON *valsobj)
{
    int32_t i,height,vout; char *coinaddr; struct basilisk_value *v; uint64_t value = 0; bits256 txid;
    txid = jbits256(valsobj,"txid");
    vout = jint(valsobj,"vout");
    coinaddr = jstr(valsobj,"address");
    if ( coin != 0 && basilisk_bitcoinavail(coin) != 0 )
    {
        if ( (coin->VALIDATENODE != 0 || coin->RELAYNODE != 0) && coinaddr != 0 && coinaddr[0] != 0 )
        {
            if ( iguana_unspentindfind(coin,coinaddr,0,0,&value,&height,txid,vout,coin->bundlescount) > 0 )
            {
                printf("bitcoinvalue found iguana\n");
                Lptr->retstr = basilisk_valuestr(coin,coinaddr,value,height,txid,vout);
                return(Lptr);
            }
        } //else return(bitcoin_value(coin,txid,vout,coinaddr));
        Lptr->retstr = clonestr("{\"error\":\"basilisk value missing address\"}");
        return(Lptr);
    }
    //printf("Scan basilisks values\n");
    if ( (v= myinfo->basilisks.values) != 0 )
    {
        for (i=0; i<myinfo->basilisks.numvalues; i++,v++)
        {
            if ( v->vout == vout && bits256_cmp(txid,v->txid) == 0 && strcmp(v->coinaddr,coinaddr) == 0 )
            {
                //printf("bitcoinvalue local\n");
                Lptr->retstr = basilisk_valuestr(coin,coinaddr,v->value,v->height,txid,vout);
                return(Lptr);
            }
        }
    }
    //printf("bitcoinvalue issue remote\n");
    return(basilisk_issueremote(myinfo,"value",coin->symbol,valsobj,timeoutmillis,juint(valsobj,"fanout"),juint(valsobj,"minresults"),basilisktag,coin->basilisk_valuemetric));
}

double basilisk_bitcoin_rawtxmetric_dependents(struct supernet_info *myinfo,struct iguana_info *coin,struct basilisk_item *ptr,struct bitcoin_rawtxdependents *dependents)
{
    int32_t i,j,numaddrs,notfinished = 0; cJSON *childjson,*addresses; struct basilisk_item *child; double metric = 0.; char *childstr,*coinaddr; int64_t inputsum,value,txfee;
    for (i=0; i<dependents->numptrs; i++)
    {
        if ( (child= dependents->ptrs[i]) != 0 )
        {
            if ( ptr->finished != 0 )
            {
                //printf("parent finished\n");
                if ( child->finished == 0 )
                {
                    ptr->childrendone++;
                    child->finished = (uint32_t)time(NULL);
                }
            }
            else if ( child->finished == 0 )
                notfinished++;
        }
    }
    if ( notfinished != 0 )
    {
        if ( ptr->finished != 0 )
            return(-1.);
        else return(0.);
    }
    else if ( ptr->vals != 0 )
    {
        if ( (txfee= j64bits(ptr->vals,"txfee")) == 0 )
            txfee = coin->chain->txfee;
        if ( txfee == 0 )
            txfee = 10000;
        addresses = jarray(&numaddrs,ptr->vals,"addresses");
        for (inputsum=i=0; i<dependents->numptrs; i++)
        {
            if ( (child= dependents->ptrs[i]) != 0 && (childstr= child->retstr) != 0 && (coinaddr= &dependents->coinaddrs[64*i]) != 0 )
            {
                if ( (childjson= cJSON_Parse(childstr)) != 0 )
                {
                    if ( (value= j64bits(childjson,"value")) != 0 )
                    {
                        inputsum += value;
                        for (j=0; j<numaddrs; j++)
                            if ( strcmp(jstri(addresses,j),coinaddr) == 0 )
                                break;
                        if ( j == numaddrs )
                        {
                            printf("spend of invalid input address.(%s)\n",coinaddr);
                            metric = -(3. + i);
                        }
                        printf("Valid spend %.8f to %s\n",dstr(value),coinaddr);
                    }
                    free_json(childjson);
                }
                free(childstr);
                child->retstr = 0;
            }
        }
        if ( (inputsum - dependents->outputsum) != txfee )
        {
            printf("inputsum %.8f - outputsum %.8f = %.8f != txfee %.8f\n",dstr(inputsum),dstr(dependents->outputsum),dstr(inputsum)-dstr(dependents->outputsum),dstr(txfee));
            return(-1001.); // error
        }
        //printf("dependents cost %lld\n",(long long)dependents->cost);
        return(dstr(dependents->cost));
    } else return(-666.); // no vals??
}

double basilisk_bitcoin_rawtxmetric(struct supernet_info *myinfo,struct basilisk_item *ptr,char *resultstr)
{
    cJSON *txobj,*vouts,*vin,*sobj,*addrs,*vins,*argvals,*resultsobj,*addresses; int64_t outputsum=0,amount=0,cost = 0; int32_t i,m,numaddrs,spendlen,n; struct iguana_msgtx msgtx; uint8_t extraspace[8192],script[IGUANA_MAXSCRIPTSIZE],serialized[16384],asmtype; struct vin_info V; char *scriptstr,*changeaddr,*coinaddr,*rawtx,*spendscriptstr; bits256 txid; struct iguana_info *coin; struct basilisk_item Lsubptr,*child; struct bitcoin_rawtxdependents *dependents=0; double metric; uint32_t locktime;
    if ( (coin= iguana_coinfind(ptr->symbol)) != 0 )
    {
        if ( (dependents= ptr->dependents) != 0 )
        {
            if ( (metric= basilisk_bitcoin_rawtxmetric_dependents(myinfo,coin,ptr,dependents)) != 0. )
            {
                for (i=0; i<dependents->numptrs; i++)
                    if ( (child= dependents->ptrs[i]) != 0 )
                        child->parent = 0;
            }
            return(metric);
        }
        if ( (resultsobj= cJSON_Parse(resultstr)) == 0 || (vins= jobj(resultsobj,"vins")) == 0 || (rawtx= jstr(resultsobj,"rawtx")) == 0 )
        {
            if ( resultsobj != 0 )
                free_json(resultsobj);
            printf("resultstr error.(%s)\n",resultstr);
            return(-1.); // error
        }
        if ( (spendscriptstr= jstr(ptr->vals,"spendscript")) != 0 )
        {
            spendlen = (int32_t)strlen(spendscriptstr) >> 1;
            decode_hex(script,spendlen,spendscriptstr);
        }
        changeaddr = jstr(ptr->vals,"changeaddr");
        locktime = juint(ptr->vals,"locktime");
        amount = j64bits(ptr->vals,"amount");
        addresses = jarray(&numaddrs,ptr->vals,"addresses");
        if ( (txobj= bitcoin_hex2json(coin,&txid,&msgtx,rawtx,extraspace,sizeof(extraspace),serialized)) != 0 )
        {
            //printf("GOT VINS.(%s) rawtx.(%s) out0 %.8f\n",jprint(vins,0),rawtx,dstr(msgtx.vouts[0].value));
            if ( juint(txobj,"locktime") != locktime )
            {
                printf("locktime mismatch %u != %u\n",juint(txobj,"locktime"),locktime);
                return(-2.); // error
            }
            else if ( jobj(txobj,"error") == 0 && cJSON_GetArraySize(vins) == msgtx.tx_in )
            {
                dependents = calloc(1,sizeof(*dependents) + msgtx.tx_in*(sizeof(*dependents->results) + sizeof(*dependents->ptrs) + 64));
                dependents->results = (void *)&dependents->ptrs[msgtx.tx_in];
                dependents->coinaddrs = (void *)&dependents->results[msgtx.tx_in];
                dependents->numptrs = msgtx.tx_in;
                ptr->dependents = dependents;
                ptr->numchildren = dependents->numptrs;
                for (i=0; i<msgtx.tx_in; i++)
                {
                    vin = jitem(vins,i);
                    if ( (sobj= jobj(vin,"scriptPubKey")) != 0 && (scriptstr= jstr(sobj,"hex")) != 0 )
                    {
                        memset(&V,0,sizeof(V));
                        V.spendlen = (int32_t)strlen(scriptstr) >> 1;
                        decode_hex(V.spendscript,V.spendlen,scriptstr);
                        asmtype = _iguana_calcrmd160(coin,&V);
                        coinaddr = &dependents->coinaddrs[64 * i];
                        //if ( asmtype == IGUANA_SCRIPT_76A988AC || asmtype == IGUANA_SCRIPT_AC || asmtype == IGUANA_SCRIPT_76AC || asmtype == IGUANA_SCRIPT_P2SH )
                        bitcoin_address(coinaddr,coin->chain->pubtype,V.rmd160,20);
                        if ( (argvals= cJSON_CreateObject()) != 0 )
                        {
                            jaddbits256(argvals,"txid",jbits256(vin,"txid"));
                            jaddnum(argvals,"timeout",ptr->expiration - OS_milliseconds());
                            jaddnum(argvals,"vout",jint(vin,"vout"));
                            jaddstr(argvals,"address",coinaddr);
                            if ( (dependents->ptrs[i]= basilisk_bitcoinvalue(&Lsubptr,myinfo,coin,0,rand(),(ptr->expiration - OS_milliseconds()) * .777,argvals)) != 0 )
                            {
                                if ( dependents->ptrs[i] == &Lsubptr )
                                {
                                    dependents->results[i] = Lsubptr.retstr;
                                    dependents->ptrs[i] = 0;
                                }
                                else dependents->ptrs[i]->parent = ptr;
                            }
                            free_json(argvals);
                        }
                    } else printf("cant find spend info.(%s)\n",jprint(vin,0));
                }
                if ( (vouts= jarray(&n,txobj,"vout")) != 0 && n == msgtx.tx_out )
                {
                    for (i=0; i<msgtx.tx_out; i++)
                    {
                        outputsum += msgtx.vouts[i].value;
                        //for (j=0; j<25; j++)
                        //    printf("%02x",msgtx.vouts[i].pk_script[j]);
                        //printf(" <- pk_script i.%d of %d: scriptlen.%d %s\n",i,msgtx.tx_out,spendlen,spendscriptstr);
                        if ( spendlen == msgtx.vouts[i].pk_scriptlen && memcmp(script,msgtx.vouts[i].pk_script,spendlen) == 0 )
                        {
                            //printf("set spentsatosis %.8f\n",dstr(msgtx.vouts[i].value));
                            dependents->spentsatoshis = msgtx.vouts[i].value;
                            continue;
                        }
                        else
                        {
                            if ( (sobj= jobj(jitem(vouts,i),"scriptPubKey")) != 0 && (addrs= jarray(&m,sobj,"addresses")) != 0 )
                            {
                                if ( m == 1 && strcmp(jstri(addrs,0),changeaddr) == 0 )
                                {
                                    dependents->change = msgtx.vouts[i].value;
                                    printf("verify it is normal spend for %s %.8f\n",changeaddr,dstr(msgtx.vouts[i].value));
                                    continue;
                                }
                            }
                        }
                        cost += msgtx.vouts[i].value;
                        //printf("boost cost %.8f\n",dstr(msgtx.vouts[i].value));
                    }
                }
            }
            free_json(txobj);
        }
    }
    if ( dependents->spentsatoshis != amount )
    {
        printf("spentsatoshis %.8f != expected %.8f, change %.8f\n",dstr(dependents->spentsatoshis),dstr(amount),dstr(dependents->change));
        return(-1000.); // error
    }
    if ( (dependents->outputsum= outputsum) <= 0 )
    {
        printf("illegal outputsum %.8f\n",dstr(outputsum));
        return(-1001.); // error
    }
    if ( cost == 0 )
        cost = 1;
    dependents->cost = cost;
    return(0.);
}

void *basilisk_bitcoinrawtx(struct basilisk_item *Lptr,struct supernet_info *myinfo,struct iguana_info *coin,char *remoteaddr,uint32_t basilisktag,int32_t timeoutmillis,cJSON *valsobj)
{
    uint8_t buf[IGUANA_MAXSCRIPTSIZE]; int32_t minconf,spendlen; cJSON *vins,*addresses,*txobj = 0; uint32_t locktime; char *spendscriptstr,*changeaddr,*rawtx = 0; int64_t amount,txfee;
    vins = 0;
    changeaddr = jstr(valsobj,"changeaddr");
    spendscriptstr = jstr(valsobj,"spendscript");
    amount = j64bits(valsobj,"amount");
    if ( (txfee= j64bits(valsobj,"txfee")) == 0 )
        txfee = coin->chain->txfee;
    if ( txfee == 0 )
        txfee = 10000;
    minconf = juint(valsobj,"minconf");
    locktime = juint(valsobj,"locktime");
    addresses = jobj(valsobj,"addresses");
    if ( changeaddr == 0 || changeaddr[0] == 0 || spendscriptstr == 0 || spendscriptstr[0] == 0 || amount == 0 || addresses == 0 )
    {
        Lptr->retstr = clonestr("{\"error\":\"invalid changeaddr or spendscript or addresses\"}");
        return(Lptr);
    }
    if ( coin != 0 && basilisk_bitcoinavail(coin) != 0 )
    {
        if ( coin->VALIDATENODE != 0 || coin->RELAYNODE != 0 )
        {
            if ( (txobj= bitcoin_txcreate(coin,locktime)) != 0 )
            {
                spendlen = (int32_t)strlen(spendscriptstr) >> 1;
                decode_hex(buf,spendlen,spendscriptstr);
                bitcoin_txoutput(coin,txobj,buf,spendlen,amount);
                rawtx = iguana_calcrawtx(myinfo,coin,&vins,txobj,amount,changeaddr,txfee,addresses,minconf);
                printf("generated.(%s) vins.(%s)\n",rawtx,vins!=0?jprint(vins,0):"");
            }
            else
            {
                Lptr->retstr = clonestr("{\"error\":\"couldnt create rawtx locally\"}");
                return(Lptr);
            }
        } //else rawtx = bitcoin_calcrawtx(myinfo,coin,vinsp,satoshis,spendscriptstr,changeaddr,txfee,addresses,minconf,locktime);
        if ( rawtx != 0 )
        {
            if ( vins != 0 )
            {
                free_json(txobj);
                valsobj = cJSON_CreateObject();
                jadd(valsobj,"vins",vins);
                jaddstr(valsobj,"rawtx",rawtx);
                free(rawtx);
                Lptr->retstr = jprint(valsobj,1);
                return(Lptr);
            } else free(rawtx);
        }
        if ( txobj != 0 )
            free_json(txobj);
        if ( vins != 0 )
            free_json(vins);
        Lptr->retstr = clonestr("{\"error\":\"couldnt create rawtx\"}");
        return(Lptr);
    }
    return(basilisk_issueremote(myinfo,"rawtx",coin->symbol,valsobj,timeoutmillis,juint(valsobj,"fanout"),juint(valsobj,"minresults"),basilisktag,coin->basilisk_rawtxmetric));
}

