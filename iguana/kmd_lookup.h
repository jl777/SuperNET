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

#ifndef INCLUDE_KMDLOOKUP_H
#define INCLUDE_KMDLOOKUP_H

struct kmd_voutinfo
{
    bits256 spendtxid;
    uint64_t amount;
    uint16_t spendvini;
    uint8_t type_rmd160[21], pad;
} PACKED;

struct kmd_transaction
{
    bits256 txid; int32_t height,numvouts; uint32_t timestamp,pad;
    struct kmd_voutinfo vouts[];
};

struct kmd_transactionhh
{
    UT_hash_handle hh;
    struct kmd_transaction *tx;
    int32_t numvouts;
    struct kmd_transactionhh *ptrs[];
};

struct kmd_addresshh
{
    UT_hash_handle hh;
    uint8_t type_rmd160[21], pad;
    struct kmd_transactionhh *prev,*lastprev;
};

struct kmd_addresshh *_kmd_address(struct iguana_info *coin,uint8_t type_rmd160[21])
{
    struct kmd_addresshh *addr;
    portable_mutex_lock(&coin->kmdmutex);
    HASH_FIND(hh,coin->kmd_addresses,type_rmd160,21,addr);
    portable_mutex_unlock(&coin->kmdmutex);
    if ( addr != 0 && 0 )
    {
        char coinaddr[64];
        bitcoin_address(coinaddr,type_rmd160[0],&type_rmd160[1],20);
        printf("%s found (%s) %02x\n",coin->symbol,coinaddr,type_rmd160[0]);
    }
    return(addr);
}

struct kmd_addresshh *_kmd_addressadd(struct iguana_info *coin,uint8_t type_rmd160[21])
{
    struct kmd_addresshh *addr;
    addr = calloc(1,sizeof(*addr));
    memcpy(addr->type_rmd160,type_rmd160,21);
    if ( 0 )
    {
        char coinaddr[64];
        bitcoin_address(coinaddr,type_rmd160[0],&type_rmd160[1],20);
        printf("%s NEW ADDRESS.(%s) %02x\n",coin->symbol,coinaddr,type_rmd160[0]);
    }
    portable_mutex_lock(&coin->kmdmutex);
    HASH_ADD_KEYPTR(hh,coin->kmd_addresses,addr->type_rmd160,21,addr);
    portable_mutex_unlock(&coin->kmdmutex);
    return(addr);
}

struct kmd_addresshh *kmd_address(struct iguana_info *coin,char *coinaddr)
{
    uint8_t type_rmd160[21];
    bitcoin_addr2rmd160(&type_rmd160[0],&type_rmd160[1],coinaddr);
    return(_kmd_address(coin,type_rmd160));
}

struct kmd_transactionhh *kmd_transaction(struct iguana_info *coin,bits256 txid)
{
    struct kmd_transactionhh *tx;
    portable_mutex_lock(&coin->kmdmutex);
    HASH_FIND(hh,coin->kmd_transactions,txid.bytes,sizeof(txid),tx);
    portable_mutex_unlock(&coin->kmdmutex);
    return(tx);
}

int32_t kmd_transactionvin(struct iguana_info *coin,bits256 spendtxid,int32_t vini,bits256 txid,int32_t vout)
{
    struct kmd_transactionhh *ptr,*spendptr=0;
    if ( bits256_nonz(txid) == 0 || vout < 0 )
        return(0); // coinbase must be
    if ( (ptr= kmd_transaction(coin,txid)) != 0 && vout < ptr->numvouts && (spendptr= kmd_transaction(coin,spendtxid)) != 0 )
    {
        ptr->ptrs[(vout<<1) + 1] = spendptr;
        ptr->tx->vouts[vout].spendtxid = spendtxid;
        ptr->tx->vouts[vout].spendvini = vini;
        return(0);
    }
    char str[65]; printf("vin error %s vout.%d vs ptr %p [%d] spent.%p\n",bits256_str(str,txid),vout,ptr,ptr!=0?ptr->numvouts:-1,spendptr);
    return(-1);
}

void kmd_transactionvout(struct iguana_info *coin,struct kmd_transactionhh *ptr,int32_t vout,uint64_t amount,uint8_t type_rmd160[21],bits256 spendtxid,int32_t spendvini)
{
    struct kmd_addresshh *addr; struct kmd_transaction *tx = 0;
    //printf("ht.%d VOUT %d %.8f\n",ptr->tx->height,vout,dstr(amount));
    if ( vout < ptr->numvouts && (tx= ptr->tx) != 0 )
    {
        tx->vouts[vout].spendtxid = spendtxid;
        tx->vouts[vout].spendvini = spendvini;
        tx->vouts[vout].amount = amount;
        memcpy(tx->vouts[vout].type_rmd160,type_rmd160,21);
        if ( coin->kmd_didinit != 0 && coin->kmd_txidfp != 0 )
            fwrite(tx,1,sizeof(*tx) + tx->numvouts*sizeof(*tx->vouts),coin->kmd_txidfp);
        if ( (addr= _kmd_address(coin,type_rmd160)) == 0 )
            addr = _kmd_addressadd(coin,type_rmd160);
        if ( addr != 0 )
        {
            if ( addr->prev != ptr )
            {
                ptr->ptrs[vout << 1] = addr->prev;
                addr->lastprev = addr->prev;
                addr->prev = ptr;
            }
            else
            {
                //printf("tricky case same address in different vouts, make sure backlink is right\n");
                ptr->ptrs[vout<<1] = addr->lastprev;
            }
        } else printf("kmd_transactionvout unexpected null addr\n");
    } else printf("vout.%d wont fit into numvouts.[%d] or null tx.%p\n",vout,ptr->numvouts,tx);
}

struct kmd_transactionhh *kmd_transactionadd(struct iguana_info *coin,struct kmd_transaction *tx,int32_t numvouts)
{
    struct kmd_transactionhh *ptr; //char str[65];
    if ( (ptr= kmd_transaction(coin,tx->txid)) == 0 )
    {
        ptr = calloc(1,sizeof(*ptr) + (sizeof(*ptr->ptrs)*numvouts*2));
        ptr->numvouts = numvouts;
        ptr->tx = tx;
        portable_mutex_lock(&coin->kmdmutex);
        //char str[65]; printf("%s ht.%d u.%u NEW TXID.(%s) vouts.[%d]\n",coin->symbol,tx->height,tx->timestamp,bits256_str(str,tx->txid),numvouts);
        HASH_ADD_KEYPTR(hh,coin->kmd_transactions,tx->txid.bytes,sizeof(tx->txid),ptr);
        portable_mutex_unlock(&coin->kmdmutex);
    } // else printf("warning adding already existing txid %s\n",bits256_str(str,tx->txid));
    return(ptr);
}

struct kmd_transaction *kmd_transactionalloc(bits256 txid,int32_t height,uint32_t timestamp,int32_t numvouts)
{
    struct kmd_transaction *tx;
    tx = calloc(1,sizeof(*tx) + sizeof(struct kmd_voutinfo)*numvouts);
    tx->numvouts = numvouts;
    tx->txid = txid;
    tx->height = height;
    tx->timestamp = timestamp;
    return(tx);
}

void kmd_flushfiles(struct iguana_info *coin)
{
    if ( coin->kmd_txidfp != 0 )
        fflush(coin->kmd_txidfp);
}

FILE *kmd_txidinit(struct iguana_info *coin)
{
    int32_t i; FILE *fp; char fname[1024],str[65]; struct kmd_transactionhh *ptr,*tmp; struct kmd_transaction T,*tx; struct kmd_voutinfo V,*vptr; long lastpos=0;
    sprintf(fname,"%s/TRANSACTIONS/%s",GLOBAL_DBDIR,coin->symbol);
    if ( (fp= fopen(fname,"rb+")) != 0 )
    {
        while ( fread(&T,1,sizeof(T),fp) == sizeof(T) )
        {
            if ( (tx= kmd_transactionalloc(T.txid,T.height,T.timestamp,T.numvouts)) != 0 )
            {
                //printf("INIT %s.[%d] ht.%d %u\n",bits256_str(str,T.txid),T.numvouts,T.height,T.timestamp);
                if ( (ptr= kmd_transactionadd(coin,tx,T.numvouts)) != 0 )
                {
                    for (i=0; i<T.numvouts; i++)
                    {
                        if ( fread(&V,1,sizeof(V),fp) == sizeof(V) )
                        {
                            kmd_transactionvout(coin,ptr,i,V.amount,V.type_rmd160,V.spendtxid,V.spendvini);
                        }
                        else
                        {
                            printf("error loading vout.%d ht.%d\n",i,T.height);
                            break;
                        }
                    }
                    if ( i == T.numvouts )
                    {
                        lastpos = ftell(fp);
                        if ( T.height > coin->kmd_height )
                            coin->kmd_height = T.height;
                    } else break;
                }
            } else break;
        }
        fseek(fp,lastpos,SEEK_SET);
        HASH_ITER(hh,coin->kmd_transactions,ptr,tmp)
        {
            for (i=0; i<ptr->numvouts; i++)
            {
                vptr = &ptr->tx->vouts[i];
                if ( vptr->spendvini >= 0 && bits256_nonz(vptr->spendtxid) != 0 )
                {
                    if ( (ptr->ptrs[(i<<1) + 1]= kmd_transaction(coin,vptr->spendtxid)) == 0 )
                        printf("cant find %s spend.%d\n",bits256_str(str,vptr->spendtxid),i);
                }
            }
        }
    } else fp = fopen(fname,"wb");
    return(fp);
}

cJSON *kmd_transactionjson(struct kmd_transactionhh *ptr,char *typestr)
{
    int32_t i; char coinaddr[64]; cJSON *item,*array,*obj = cJSON_CreateObject();
    array = cJSON_CreateArray();
    jaddstr(obj,"type",typestr);
    jaddbits256(obj,"txid",ptr->tx->txid);
    jaddnum(obj,"height",ptr->tx->height);
    jaddnum(obj,"timestamp",ptr->tx->timestamp);
    for (i=0; i<ptr->numvouts; i++)
    {
        item = cJSON_CreateObject();
        bitcoin_address(coinaddr,ptr->tx->vouts[i].type_rmd160[0],&ptr->tx->vouts[i].type_rmd160[1],20);
        jaddnum(item,coinaddr,dstr(ptr->tx->vouts[i].amount));
        jaddi(array,item);
    }
    jadd(obj,"vouts",array);
    return(obj);
}

cJSON *kmd_unspentjson(struct kmd_transaction *tx,int32_t vout)
{
    cJSON *item = cJSON_CreateObject();
    jaddbits256(item,"txid",tx->txid);
    jaddnum(item,"vout",vout);
    jaddnum(item,"amount",dstr(tx->vouts[vout].amount));
    return(item);
}

int32_t kmd_height(struct iguana_info *coin)
{
    char params[64],*curlstr; cJSON *curljson; int32_t height = 0;
    strcpy(params,"[]");
    if ( (curlstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"getinfo",params)) != 0 )
    {
        if ( (curljson= cJSON_Parse(curlstr)) != 0 )
        {
            height = juint(curljson,"blocks");
            //printf("kmd_height.%d (%s)\n",height,jprint(curljson,0));
            free_json(curljson);
        }
        free(curlstr);
    }
    return(height);
}

cJSON *kmd_listtransactions(struct iguana_info *coin,char *coinaddr,int32_t count,int32_t skip)
{
    struct kmd_addresshh *addr; struct kmd_transactionhh *ptr,*spent,*prev=0; uint8_t type_rmd160[21]; int32_t i,height,counter=0; cJSON *array = cJSON_CreateArray();
    if ( (height= kmd_height(coin)) > coin->kmd_height+3 )
        return(cJSON_Parse("[]"));
    bitcoin_addr2rmd160(&type_rmd160[0],&type_rmd160[1],coinaddr);
    if ( (addr= _kmd_address(coin,type_rmd160)) != 0 && (ptr= addr->prev) != 0 && ptr->tx != 0 )
    {
        while ( ptr != 0 )
        {
            if ( counter >= skip && counter < count+skip )
                jaddi(array,kmd_transactionjson(ptr,"received"));
            if ( ++counter >= count+skip )
                break;
            for (i=0; i<ptr->numvouts; i++)
            {
                if ( memcmp(ptr->tx->vouts[i].type_rmd160,type_rmd160,21) == 0 && (spent= ptr->ptrs[(i<<1)+1]) != 0 )
                {
                    if ( counter >= skip && counter < count+skip )
                        jaddi(array,kmd_transactionjson(spent,"sent"));
                    if ( ++counter >= count+skip )
                        break;
                    if ( ptr->ptrs[i << 1] != 0 )
                        prev = ptr->ptrs[i << 1];
                }
            }
            if ( counter >= count+skip )
                break;
            ptr = prev;
        }
    }
    return(array);
}

cJSON *kmd_gettxin(struct iguana_info *coin,bits256 txid,int32_t vout)
{
    struct kmd_transactionhh *ptr,*spendptr; struct kmd_transaction *tx; cJSON *retjson;
    if ( (ptr= kmd_transaction(coin,txid)) != 0 && (tx= ptr->tx) != 0 )
    {
        if ( vout >= ptr->numvouts )
            return(cJSON_Parse("{\"error\":\"vout too big\"}"));
        if ( (spendptr= ptr->ptrs[(vout << 1) + 1]) != 0 )
        {
            retjson = cJSON_CreateObject();
            jaddstr(retjson,"result","success");
            jaddstr(retjson,"status","spent");
            jaddnum(retjson,"height",tx->height);
            jaddnum(retjson,"timestamp",tx->timestamp);
            jaddbits256(retjson,"txid",txid);
            jaddnum(retjson,"vout",vout);
            jaddnum(retjson,"value",dstr(tx->vouts[vout].amount));
            jaddbits256(retjson,"spendtxid",tx->vouts[vout].spendtxid);
            jaddnum(retjson,"vin",tx->vouts[vout].spendvini);
        } else return(cJSON_Parse("{\"result\":\"success\",\"status\":\"unspent\"}"));
    }
    return(cJSON_Parse("{\"error\":\"txid not found\"}"));
}

cJSON *kmd_listaddress(struct iguana_info *coin,char *coinaddr,int32_t mode)
{
    struct kmd_addresshh *addr; struct kmd_transactionhh *ptr,*spent,*prev=0; uint8_t type_rmd160[21]; int32_t i,height; cJSON *array = cJSON_CreateArray();
    if ( (height= kmd_height(coin)) > coin->kmd_height+3 )
    {
        printf("height.%d > kmd_height.%d\n",height,coin->kmd_height);
        return(cJSON_Parse("[]"));
    }
    bitcoin_addr2rmd160(&type_rmd160[0],&type_rmd160[1],coinaddr);
    if ( (addr= _kmd_address(coin,type_rmd160)) != 0 && (ptr= addr->prev) != 0 && ptr->tx != 0 )
    {
        while ( ptr != 0 )
        {
            prev = 0;
            for (i=0; i<ptr->numvouts; i++)
            {
                if ( memcmp(ptr->tx->vouts[i].type_rmd160,type_rmd160,21) == 0 )
                {
                    spent = ptr->ptrs[(i<<1) + 1];
                    if ( (mode == 0 && spent == 0) || (mode == 1 && spent != 0) )
                        jaddi(array,kmd_unspentjson(ptr->tx,i));
                    if ( ptr->ptrs[i<<1] != 0 )
                        prev = ptr->ptrs[i<<1];
                }
            }
            ptr = prev;
        }
    }
    return(array);
}

cJSON *kmd_listunspent(struct iguana_info *coin,char *coinaddr)
{
    return(kmd_listaddress(coin,coinaddr,0));
}

cJSON *kmd_listspent(struct iguana_info *coin,char *coinaddr)
{
    return(kmd_listaddress(coin,coinaddr,1));
}

int64_t _kmd_getbalance(struct iguana_info *coin,char *coinaddr,int64_t *unspentp,int64_t *spentp)
{
    int32_t iter,i,n; cJSON *array,*item; int64_t value;
    for (iter=0; iter<2; iter++)
    {
        if ( (array= kmd_listaddress(coin,coinaddr,iter)) != 0 )
        {
            if ( (n= cJSON_GetArraySize(array)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    item = jitem(array,i);
                    if ( (value= jdouble(item,"amount")*SATOSHIDEN) != 0 || (value= jdouble(item,"value")*SATOSHIDEN) != 0 )
                    {
                        if ( iter == 0 )
                            *unspentp += value;
                        else *spentp += value;
                    }
                }
            }
            free_json(array);
        }
    }
    return(*unspentp - *spentp);
}

cJSON *kmd_getbalance(struct iguana_info *coin,char *coinaddr)
{
    cJSON *retjson; int64_t s,u,spent=0,unspent=0,balance=0; struct kmd_addresshh *addr,*tmp; char address[64];
    if ( strcmp(coinaddr,"*") == 0 )
    {
        HASH_ITER(hh,coin->kmd_addresses,addr,tmp)
        {
            bitcoin_address(address,addr->type_rmd160[0],&addr->type_rmd160[1],20);
            s = u = 0;
            balance += _kmd_getbalance(coin,address,&u,&s);
            printf("%s (%.8f - %.8f) %.8f -> %.8f\n",address,dstr(u),dstr(s),dstr(u)-dstr(s),dstr(balance));
            unspent += u;
            spent += s;
        }
    } else balance = _kmd_getbalance(coin,coinaddr,&unspent,&spent);
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"result","success");
    jaddnum(retjson,"unspents",dstr(unspent));
    jaddnum(retjson,"spents",dstr(spent));
    jaddnum(retjson,"balance",dstr(balance));
    return(retjson);
}

char *kmd_bitcoinblockhashstr(char *coinstr,char *serverport,char *userpass,int32_t height)
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

cJSON *kmd_blockjson(int32_t *heightp,char *coinstr,char *serverport,char *userpass,char *blockhashstr,int32_t height)
{
    cJSON *json = 0; int32_t flag = 0; char buf[1024],*blocktxt = 0;
    if ( blockhashstr == 0 )
        blockhashstr = kmd_bitcoinblockhashstr(coinstr,serverport,userpass,height), flag = 1;
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

int32_t _kmd_bitcoinscan(struct iguana_info *coin)
{
    int32_t h,num=0,loadheight,i,n,j,iter,numtxids,numvins,numvouts,flag=0,height=-1; cJSON *txjson,*vouts,*vins,*blockjson,*txids,*vout,*vin,*sobj,*addresses; bits256 zero,txid; char *curlstr,params[128],str[65]; struct kmd_transactionhh *ptr; struct kmd_transaction *tx; uint8_t type_rmd160[21];
    if ( coin->kmd_didinit == 0 )
    {
        if ( (coin->kmd_txidfp= kmd_txidinit(coin)) == 0 )
            printf("error initializing %s.kmd lookups\n",coin->symbol);
        coin->kmd_didinit = 1;
    }
    height = kmd_height(coin);
    loadheight = coin->kmd_height+1;
    while ( loadheight < height )
    {
        flag = 0;
        if ( (loadheight % 1000) == 0 )
            printf("loading ht.%d\n",loadheight);
        if ( (blockjson= kmd_blockjson(&h,coin->symbol,coin->chain->serverport,coin->chain->userpass,0,loadheight)) != 0 )
        {
            if ( (txids= jarray(&numtxids,blockjson,"tx")) != 0 )
            {
                for (iter=0; iter<2; iter++)
                for (i=0; i<numtxids; i++)
                {
                    memset(&zero,0,sizeof(zero));
                    txid = jbits256(jitem(txids,i),0);
                    if ( iter == 0 && kmd_transaction(coin,txid) != 0 )
                    {
                        //printf("already have txid.%s\n",bits256_str(str,txid));
                        continue;
                    }
                    sprintf(params,"[\"%s\", 1]",bits256_str(str,txid));
                    if ( (curlstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"getrawtransaction",params)) != 0 )
                    {
                        if ( (txjson= cJSON_Parse(curlstr)) != 0 )
                        {
                            if ( bits256_cmp(txid,jbits256(txjson,"txid")) != 0 )
                            {
                                printf("txid mismatch error ht.%d i.%d\n",loadheight,i);
                                continue;
                            }
                            vouts = jarray(&numvouts,txjson,"vout");
                            vins = jarray(&numvins,txjson,"vin");
                            tx = 0;
                            ptr = 0;
                            if ( iter == 0 )
                            {
                                if ( (tx= kmd_transactionalloc(txid,loadheight,jint(txjson,"blocktime"),numvouts)) != 0 )
                                        ptr = kmd_transactionadd(coin,tx,numvouts);
                                else printf("error init tx ptr.%p tx.%p\n",ptr,tx);
                            }
                            else
                            {
                                if ( (ptr= kmd_transaction(coin,txid)) != 0 )
                                    tx = ptr->tx;
                            }
                            if ( ptr != 0 && tx != 0 )
                            {
                                if ( iter == 0 )
                                {
                                    sobj = addresses = 0;
                                    for (j=0; j<numvouts; j++)
                                    {
                                        vout = jitem(vouts,j);
                                        if ( (sobj= jobj(vout,"scriptPubKey")) != 0 && (addresses= jarray(&n,sobj,"addresses")) != 0 )
                                        {
                                            bitcoin_addr2rmd160(&type_rmd160[0],&type_rmd160[1],jstri(addresses,0));
                                            kmd_transactionvout(coin,ptr,j,jdouble(vout,"value")*SATOSHIDEN,type_rmd160,zero,-1);
                                        } // else printf("missing sobj.%p or addresses.%p (%s)\n",sobj,addresses,jprint(vout,0)); //likely OP_RETURN
                                        sobj = addresses = 0;
                                    }
                                }
                                else
                                {
                                    for (j=0; j<numvins; j++)
                                    {
                                        vin = jitem(vins,j);
                                        if ( kmd_transactionvin(coin,txid,j,jbits256(vin,"txid"),jint(vin,"vout")) < 0 )
                                        {
                                            printf("error i.%d of numvins.%d (%s)\n",j,numvins,jprint(vin,0));
                                            flag++;
                                        }
                                    }
                                }
                            } else printf("incomplete at ht.%d i.%d %p %p\n",loadheight,i,ptr,tx);
                            free_json(txjson);
                        } else printf("parseerror.(%s)\n",curlstr);
                        free(curlstr);
                    }
                }
                num++;
                kmd_flushfiles(coin);
            }
            free_json(blockjson);
        }
        if ( flag != 0 || num > 5000 )
            break;
        coin->kmd_height = loadheight++;
    }
    return(num);
}

void kmd_bitcoinscan()
{
    char *retstr; cJSON *array; int32_t i,n; struct iguana_info *coin;
    if ( (retstr= dpow_notarychains(0,0,0,0)) != 0 )
    {
        if ( (array= cJSON_Parse(retstr)) != 0 )
        {
            if ( (n= cJSON_GetArraySize(array)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    if ( (coin= iguana_coinfind(jstri(array,i))) != 0 && strcmp(coin->symbol,"BTC") != 0 )
                    {
                        if ( strcmp("KMD",coin->symbol) == 0 )
                            _kmd_bitcoinscan(coin);
                    }
                }
            }
            free_json(array);
        }
        free(retstr);
    }
}

#endif
