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

#include "bitcoin.h"

cJSON *instantdex_statemachinejson(struct bitcoin_swapinfo *swap);

char *bitcoind_passthru(char *coinstr,char *serverport,char *userpass,char *method,char *params)
{
    return(bitcoind_RPC(0,coinstr,serverport,userpass,method,params));
}

int32_t bitcoin_addr2rmd160(uint8_t *addrtypep,uint8_t rmd160[20],char *coinaddr)
{
    bits256 hash; uint8_t *buf,_buf[25]; int32_t len;
    memset(rmd160,0,20);
    *addrtypep = 0;
    buf = _buf;
    if ( (len= bitcoin_base58decode(buf,coinaddr)) >= 4 )
    {
        // validate with trailing hash, then remove hash
        hash = bits256_doublesha256(0,buf,len - 4);
        *addrtypep = *buf;
        memcpy(rmd160,buf+1,20);
        if ( (buf[len - 4]&0xff) == hash.bytes[31] && (buf[len - 3]&0xff) == hash.bytes[30] &&(buf[len - 2]&0xff) == hash.bytes[29] &&(buf[len - 1]&0xff) == hash.bytes[28] )
        {
            //printf("coinaddr.(%s) valid checksum addrtype.%02x\n",coinaddr,*addrtypep);
            return(20);
        }
        else
        {
            //char hexaddr[64];
            //btc_convaddr(hexaddr,coinaddr);
            //for (i=0; i<len; i++)
            //    printf("%02x ",buf[i]);
            char str[65]; printf("\nhex checkhash.(%s) len.%d mismatch %02x %02x %02x %02x vs %02x %02x %02x %02x (%s)\n",coinaddr,len,buf[len - 4]&0xff,buf[len - 3]&0xff,buf[len - 2]&0xff,buf[len - 1]&0xff,hash.bytes[31],hash.bytes[30],hash.bytes[29],hash.bytes[28],bits256_str(str,hash));
        }
    }
	return(0);
}

char *bitcoin_address(char *coinaddr,uint8_t addrtype,uint8_t *pubkey_or_rmd160,int32_t len)
{
    int32_t i; uint8_t data[25]; bits256 hash;// char checkaddr[65];
    if ( len != 20 )
        calc_rmd160_sha256(data+1,pubkey_or_rmd160,len);
    else memcpy(data+1,pubkey_or_rmd160,20);
    //btc_convrmd160(checkaddr,addrtype,data+1);
    data[0] = addrtype;
    hash = bits256_doublesha256(0,data,21);
    for (i=0; i<4; i++)
        data[21+i] = hash.bytes[31-i];
    if ( (coinaddr= bitcoin_base58encode(coinaddr,data,25)) != 0 )
    {
        //uint8_t checktype,rmd160[20];
        //bitcoin_addr2rmd160(&checktype,rmd160,coinaddr);
        //if ( strcmp(checkaddr,coinaddr) != 0 )
        //    printf("checkaddr.(%s) vs coinaddr.(%s) %02x vs [%02x] memcmp.%d\n",checkaddr,coinaddr,addrtype,checktype,memcmp(rmd160,data+1,20));
    }
    return(coinaddr);
}

int32_t bitcoin_validaddress(struct iguana_info *coin,char *coinaddr)
{
    uint8_t rmd160[20],addrtype; char checkaddr[128];
    if ( coin == 0 || coinaddr == 0 || coinaddr[0] == 0 )
        return(-1);
    else if ( bitcoin_addr2rmd160(&addrtype,rmd160,coinaddr) < 0 )
        return(-1);
    else if ( addrtype != coin->chain->pubtype && addrtype != coin->chain->p2shtype )
        return(-1);
    else if ( bitcoin_address(checkaddr,addrtype,rmd160,sizeof(rmd160)) != checkaddr || strcmp(checkaddr,coinaddr) != 0 )
        return(-1);
    return(0);
}

int32_t base58encode_checkbuf(uint8_t addrtype,uint8_t *data,int32_t data_len)
{
    uint8_t i; bits256 hash;
    data[0] = addrtype;
    //for (i=0; i<data_len+1; i++)
    //    printf("%02x",data[i]);
    //printf(" extpriv -> ");
    hash = bits256_doublesha256(0,data,(int32_t)data_len+1);
    //for (i=0; i<32; i++)
    //    printf("%02x",hash.bytes[i]);
    //printf(" checkhash\n");
    for (i=0; i<4; i++)
        data[data_len+i+1] = hash.bytes[31-i];
    return(data_len + 5);
}

int32_t bitcoin_wif2priv(uint8_t *addrtypep,bits256 *privkeyp,char *wifstr)
{
    int32_t len = -1; bits256 hash; uint8_t buf[64];
    if ( (len= bitcoin_base58decode(buf,wifstr)) >= 4 )
    {
        // validate with trailing hash, then remove hash
        hash = bits256_doublesha256(0,buf,len - 4);
        *addrtypep = *buf;
        memcpy(privkeyp,buf+1,32);
        if ( (buf[len - 4]&0xff) == hash.bytes[31] && (buf[len - 3]&0xff) == hash.bytes[30] &&(buf[len - 2]&0xff) == hash.bytes[29] &&(buf[len - 1]&0xff) == hash.bytes[28] )
        {
            //printf("coinaddr.(%s) valid checksum\n",coinaddr);
            return(32);
        }
    }
    return(-1);
}

int32_t bitcoin_priv2wif(char *wifstr,bits256 privkey,uint8_t addrtype)
{
    uint8_t data[128]; int32_t len;
    memcpy(data+1,privkey.bytes,sizeof(privkey));
    data[33] = 1;
    len = base58encode_checkbuf(addrtype,data,33);
    
    if ( bitcoin_base58encode(wifstr,data,len) == 0 )
        return(-1);
    if ( 1 )
    {
        uint8_t checktype; bits256 checkpriv; char str[65],str2[65];
        if ( bitcoin_wif2priv(&checktype,&checkpriv,wifstr) == sizeof(bits256) )
        {
            if ( checktype != addrtype || bits256_cmp(checkpriv,privkey) != 0 )
                printf("(%s) -> wif.(%s) addrtype.%02x -> %02x (%s)\n",bits256_str(str,privkey),wifstr,addrtype,checktype,bits256_str(str2,checkpriv));
        }
    }
    return((int32_t)strlen(wifstr));
}

int32_t iguana_validatesigs(struct iguana_info *coin,struct iguana_msgvin *vin)
{
    // multiple coins
    // ro -> vouts collision, purgeable
    // 
    return(0);
}

#ifdef bitcoincancalulatebalances
uint64_t bitcoin_parseunspent(struct iguana_info *coin,struct bitcoin_unspent *unspent,double minconfirms,char *account,cJSON *item)
{
    char *hexstr,coinaddr[64];
    memset(unspent,0,sizeof(*unspent));
    if ( jstr(item,"address") != 0 )
    {
        safecopy(coinaddr,jstr(item,"address"),sizeof(coinaddr));
        bitcoin_addr2rmd160(&unspent->addrtype,unspent->rmd160,coinaddr);
        /*sprintf(args,"[\"%s\"]",coinaddr);
        wifstr = bitcoind_RPC(0,coin->symbol,coin->chain->serverport,coin->chain->userpass,"dumpprivkey",args);
        if ( wifstr != 0 )
        {
            bitcoin_wif2priv(&addrtype,&unspent->privkeys[0],wifstr);
            //printf("wifstr.(%s) -> %s\n",wifstr,bits256_str(str,unspent->privkeys[0]));
            free(wifstr);
        } else fprintf(stderr,"error (%s) cant find privkey\n",coinaddr);*/
    }
    if ( (account == 0 || jstr(item,"account") == 0 || strcmp(account,jstr(item,"account")) == 0) && (minconfirms <= 0 || juint(item,"confirmations") >= minconfirms-SMALLVAL) )
    {
        if ( (hexstr= jstr(item,"scriptPubKey")) != 0 )
        {
            unspent->spendlen = (int32_t)strlen(hexstr) >> 1;
            if ( unspent->spendlen < sizeof(unspent->spendscript) )
                decode_hex(unspent->spendscript,unspent->spendlen,hexstr);
        }
        unspent->txid = jbits256(item,"txid");
        unspent->value = SATOSHIDEN * jdouble(item,"amount");
        unspent->vout = jint(item,"vout");
        //char str[65]; printf("(%s) -> %s %.8f scriptlen.%d\n",jprint(item,0),bits256_str(str,unspent->txid),dstr(unspent->value),unspent->scriptlen);
    } else printf("skip.(%s) minconfirms.%f\n",jprint(item,0),minconfirms);
    return(unspent->value);
}

struct bitcoin_unspent *iguana_unspentsget(struct supernet_info *myinfo,struct iguana_info *coin,char **retstrp,double *balancep,int32_t *numunspentsp,double minconfirms,char *address)
{
    char params[128],*retstr; uint64_t value,total = 0; struct bitcoin_unspent *unspents=0; cJSON *utxo; int32_t i,n;
    *numunspentsp = 0;
    if ( retstrp != 0 )
        *retstrp = 0;
    if ( address == 0 )
        sprintf(params,"%.0f, 99999999",minconfirms);
    else sprintf(params,"%.0f, 99999999, [\"%s\"]",minconfirms,address);
    if ( (retstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"listunspent",params)) != 0 )
    {
        printf("sss unspents.(%s)\n",retstr);
        if ( (utxo= cJSON_Parse(retstr)) != 0 )
        {
            n = 0;
            if ( (*numunspentsp= cJSON_GetArraySize(utxo)) > 0 )
            {
                unspents = calloc(*numunspentsp,sizeof(*unspents));
                for (i=0; i<*numunspentsp; i++)
                {
                    value = bitcoin_parseunspent(coin,&unspents[n],minconfirms,0,jitem(utxo,i));
                    printf("i.%d n.%d value %.8f\n",i,n,dstr(value));
                    if ( value != 0 )
                    {
                        total += value;
                        n++;
                    }
                }
            }
            printf("numunspents.%d -> %d total %.8f\n",*numunspentsp,n,dstr(total));
            *numunspentsp = n;
            free_json(utxo);
        } else printf("error parsing.(%s)\n",retstr);
        if ( retstrp != 0 )
            *retstrp = retstr;
        else free(retstr);
    }
    *balancep = dstr(total);
    return(unspents);
}

struct bitcoin_unspent *iguana_bestfit(struct iguana_info *coin,struct bitcoin_unspent *unspents,int32_t numunspents,uint64_t value,int32_t mode)
{
    int32_t i; uint64_t above,below,gap,atx_value; struct bitcoin_unspent *vin,*abovevin,*belowvin;
    abovevin = belowvin = 0;
    for (above=below=i=0; i<numunspents; i++)
    {
        vin = &unspents[i];
        atx_value = vin->value;
        //printf("(%.8f vs %.8f)\n",dstr(atx_value),dstr(value));
        if ( atx_value == value )
            return(vin);
        else if ( atx_value > value )
        {
            gap = (atx_value - value);
            if ( above == 0 || gap < above )
            {
                above = gap;
                abovevin = vin;
            }
        }
        else if ( mode == 0 )
        {
            gap = (value - atx_value);
            if ( below == 0 || gap < below )
            {
                below = gap;
                belowvin = vin;
            }
        }
    }
    if ( (vin= (abovevin != 0) ? abovevin : belowvin) == 0 && mode == 1 )
        vin = unspents;
    return(vin);
}

struct bitcoin_spend *iguana_spendset(struct supernet_info *myinfo,struct iguana_info *coin,int64_t amount,int64_t txfee,cJSON *addresses,int32_t minconf)
{
    int32_t i,n,mode,maxinputs,numunspents,totalunspents = 0; struct bitcoin_unspent *ptr,*up,*ups=0,*u;
    struct bitcoin_spend *spend; double balance; int64_t remains;
    if ( (n= cJSON_GetArraySize(addresses)) > 0 )
    {
        for (i=0; i<n; i++)
        {
            if ( (u= iguana_unspentsget(myinfo,coin,0,&balance,&numunspents,minconf,jstri(addresses,i))) != 0 )
            {
                if ( ups == 0 )
                {
                    ups = u;
                    totalunspents = numunspents;
                }
                else
                {
                    ups = realloc(ups,sizeof(*ups) * (numunspents + totalunspents));
                    memcpy(&ups[totalunspents],u,sizeof(*ups) * totalunspents);
                    totalunspents += numunspents;
                    free(u);
                }
            }
        }
    }
    else if ( (ups= iguana_unspentsget(myinfo,coin,0,&balance,&totalunspents,minconf,0)) == 0 )
        return(0);
    if ( totalunspents == 0 )
        return(0);
    maxinputs = totalunspents;
    spend = calloc(1,sizeof(*spend) + sizeof(*spend->inputs) * totalunspents);
    spend->txfee = txfee;
    remains = txfee + amount;
    spend->satoshis = remains;
    ptr = spend->inputs;
    for (i=0; i<maxinputs; i++,ptr++)
    {
        for (mode=1; mode>=0; mode--)
            if ( (up= iguana_bestfit(coin,ups,totalunspents,remains,mode)) != 0 )
                break;
        if ( up != 0 )
        {
            spend->input_satoshis += up->value;
            spend->inputs[spend->numinputs++] = *up;
            // todo: update a vins array
            if ( spend->input_satoshis >= spend->satoshis )
            {
                spend->change = (spend->input_satoshis - spend->satoshis) - txfee;
                printf("numinputs %d -> (%.8f - spend %.8f) = change %.8f -> txfee %.8f vs chainfee %.8f\n",spend->numinputs,dstr(spend->input_satoshis),dstr(spend->satoshis),dstr(spend->change),dstr(spend->input_satoshis - spend->change - spend->satoshis),dstr(txfee));
                break;
            }
            memset(up,0,sizeof(*up));
            remains -= up->value;
        } else break;
    }
    if ( spend->input_satoshis >= spend->satoshis )
    {
        spend = realloc(spend,sizeof(*spend) + sizeof(*spend->inputs) * spend->numinputs);
        free(ups);
        return(spend);
    }
    else
    {
        free(spend);
        free(ups);
        return(0);
    }
}

cJSON *bitcoin_vout(uint64_t satoshis,char *paymentscriptstr)
{
    cJSON *item,*skey;
    item = cJSON_CreateObject();
    jadd64bits(item,"satoshis",satoshis);
    skey = cJSON_CreateObject();
    jaddstr(skey,"hex",paymentscriptstr);
    //printf("addoutput.(%s %s)\n",hexstr,jprint(skey,0));
    jadd(item,"scriptPubkey",skey);
    return(item);
}

char *bitcoin_calcrawtx(struct supernet_info *myinfo,struct iguana_info *coin,cJSON **vinsp,int64_t satoshis,char *paymentscriptstr,char *changeaddr,int64_t txfee,cJSON *addresses,int32_t minconf,uint32_t locktime)
{
    uint8_t addrtype,rmd160[20],script[512]; int32_t i,scriptlen; char *params,*rawtx=0; cJSON *item,*array,*vins=0,*vouts=0; struct bitcoin_spend *spend; char scriptstr[512],*voutstr;
    *vinsp = 0;
    if ( (spend= iguana_spendset(myinfo,coin,satoshis,txfee*2,addresses,minconf)) == 0 )
        return(0);
    if ( spend->input_satoshis >= satoshis+txfee*2 )
    {
        vins = cJSON_CreateArray();
        for (i=0; i<spend->numinputs; i++)
        {
            item = cJSON_CreateObject();
            jaddbits256(item,"txid",spend->inputs[i].txid);
            jaddnum(item,"vout",spend->inputs[i].vout);
            jaddi(vins,item);
        }
        vouts = cJSON_CreateArray();
        jaddi(vouts,bitcoin_vout(satoshis,paymentscriptstr));
        if ( spend->change > 0 )
        {
            if ( iguana_addressvalidate(coin,&addrtype,changeaddr) < 0 )
            {
                free(spend);
                printf("illegal destination address.(%s)\n",changeaddr);
                return(0);
            }
            bitcoin_addr2rmd160(&addrtype,rmd160,changeaddr);
            scriptlen = bitcoin_standardspend(script,0,rmd160);
            init_hexbytes_noT(scriptstr,script,scriptlen);
            jaddi(vouts,bitcoin_vout(satoshis,scriptstr));
        }
        bitcoin_addr2rmd160(&addrtype,rmd160,myinfo->myaddr.BTC);
        scriptlen = bitcoin_standardspend(script,0,rmd160);
        jaddi(vouts,bitcoin_vout(satoshis,scriptstr));
        voutstr = jprint(vouts,1);
        voutstr[0] = '{', voutstr[strlen(voutstr)-1] = '}';
        array = cJSON_CreateArray();
        jaddi(array,jduplicate(vins));
        jaddi(array,cJSON_Parse(voutstr)), free(voutstr);
        params = jprint(array,1);
        rawtx = bitcoind_passthru(coin->name,coin->chain->serverport,coin->chain->userpass,"createrawtransaction",params);
        free(params);
    }
    *vinsp = vins;
    free(spend);
    // add sigtxid to vins
    if ( locktime != 0 )
        printf("need to patch locktime\n");
    return(rawtx);
}
#endif

#define EXCHANGE_NAME "bitcoin"
#define UPDATE bitcoin ## _price
#define SUPPORTS bitcoin ## _supports
#define SIGNPOST bitcoin ## _signpost
#define TRADE bitcoin ## _trade
#define ORDERSTATUS bitcoin ## _orderstatus
#define CANCELORDER bitcoin ## _cancelorder
#define OPENORDERS bitcoin ## _openorders
#define TRADEHISTORY bitcoin ## _tradehistory
#define BALANCES bitcoin ## _balances
#define PARSEBALANCE bitcoin ## _parsebalance
#define WITHDRAW bitcoin ## _withdraw
#define CHECKBALANCE bitcoin ## _checkbalance
#define ALLPAIRS bitcoin ## _allpairs
#define FUNCS bitcoin ## _funcs
#define BASERELS bitcoin ## _baserels

static char *BASERELS[][2] = { {"btcd","btc"}, {"nxt","btc"}, {"asset","btc"} };
#include "exchange_supports.h"

double UPDATE(struct exchange_info *exchange,char *base,char *rel,struct exchange_quote *bidasks,int32_t maxdepth,double commission,cJSON *argjson,int32_t invert)
{
    cJSON *retjson,*bids,*asks; double hbla; struct supernet_info *myinfo;
    myinfo = SuperNET_MYINFO(0);
    bids = cJSON_CreateArray();
    asks = cJSON_CreateArray();
    instantdex_offerfind(myinfo,exchange,bids,asks,0,base,rel,0);
    //printf("bids.(%s) asks.(%s)\n",jprint(bids,0),jprint(asks,0));
    retjson = cJSON_CreateObject();
    cJSON_AddItemToObject(retjson,"bids",bids);
    cJSON_AddItemToObject(retjson,"asks",asks);
    hbla = exchanges777_json_orderbook(exchange,commission,base,rel,bidasks,maxdepth,retjson,0,"bids","asks",0,0,invert);
    free_json(retjson);
    return(hbla);
}

char *PARSEBALANCE(struct exchange_info *exchange,double *balancep,char *coinstr,cJSON *argjson)
{
    cJSON *item;
    *balancep = 0;
    if ( (item= jobj(argjson,coinstr)) != 0 )
    {
        *balancep = jdouble(item,"balance");
        return(jprint(item,0));
    }
    return(clonestr("{\"error\":\"no item for specified coin\"}"));
}

cJSON *BALANCES(struct exchange_info *exchange,cJSON *argjson)
{
    double balance; int16_t hdrsi; uint32_t unspentind; int32_t i,minconfirms,numunspents,max; struct iguana_info *coin,*tmp; struct supernet_info *myinfo; cJSON *retjson,*array,*item,*addresses=0; int64_t *unspents=0,value,avail;
    retjson = cJSON_CreateArray();
    myinfo = SuperNET_accountfind(argjson);
    //portable_mutex_lock(&myinfo->allcoins_mutex);
    HASH_ITER(hh,myinfo->allcoins,coin,tmp)
    {
        balance = 0.;
        minconfirms = juint(argjson,"minconfirms");
        if ( minconfirms < coin->minconfirms )
            minconfirms = coin->minconfirms;
        max = 100000;
        unspents = calloc(max,sizeof(*unspents));
        if ( (numunspents= iguana_unspentslists(myinfo,coin,&avail,unspents,max,((uint64_t)1 << 62),minconfirms,addresses)) > 0 )
        {
            array = cJSON_CreateArray();
            for (i=0; i<numunspents; i++)
            {
                item = cJSON_CreateArray();
                hdrsi = (int16_t)(unspents[(i << 1)] >> 32);
                unspentind = (uint32_t)unspents[(i << 1)];
                value = unspents[(i << 1) + 1];
                jaddinum(item,hdrsi);
                jaddinum(item,unspentind);
                jaddinum(item,dstr(value));
                jaddi(array,item);
            }
            item = cJSON_CreateObject();
            jadd(item,"unspents",array);
            jaddnum(item,"numunspents",numunspents);
            jaddnum(item,"balance",dstr(avail));
            jadd(retjson,coin->symbol,item);
        }
        if ( unspents != 0 )
            free(unspents);
    }
    //portable_mutex_unlock(&myinfo->allcoins_mutex);
    return(retjson);
}

int32_t is_valid_BTCother(char *other)
{
    if ( iguana_coinfind(other) != 0 )
        return(1);
    else if ( strcmp(other,"NXT") == 0 || strcmp(other,"nxt") == 0 )
        return(1);
    else if ( is_decimalstr(other) > 0 )
        return(1);
    else return(0);
}

uint64_t TRADE(int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume,cJSON *argjson)
{
    char *str,*retstr,coinaddr[64]; int32_t added; uint64_t txid = 0; cJSON *json=0; struct instantdex_accept *ap; struct supernet_info *myinfo; struct iguana_info *other;
    myinfo = SuperNET_MYINFO(0);//SuperNET_accountfind(argjson);
    //printf("TRADE with myinfo.%p\n",myinfo);
    if ( retstrp != 0 )
        *retstrp = 0;
    if ( strcmp(base,"BTC") == 0 || strcmp(base,"btc") == 0 )
    {
        base = rel;
        rel = "BTC";
        dir = -dir;
        volume *= price;
        price = 1. / price;
    }
    if ( is_valid_BTCother(base) != 0 && (strcmp(rel,"BTC") == 0 || strcmp(rel,"btc") == 0) )
    {
        if ( dotrade == 0 )
        {
            if ( retstrp != 0 )
                *retstrp = clonestr("{\"result\":\"would issue new trade\"}");
        }
        else
        {
            if ( (other= iguana_coinfind(base)) != 0 )
            {
                //bitcoin_pubkey33(0,pubkey,myinfo->persistent_priv);
                bitcoin_address(coinaddr,other->chain->pubtype,myinfo->persistent_pubkey33,33);
                jaddstr(argjson,base,coinaddr);
            }
            else if ( strcmp(base,"NXT") == 0 || (is_decimalstr(base) > 0 && strlen(base) > 13) )
            {
                printf("NXT is not yet\n");
                return(0);
            }
            else return(0);
            json = cJSON_CreateObject();
            jaddstr(json,"base",base);
            jaddstr(json,"rel","BTC");
            jaddnum(json,dir > 0 ? "maxprice" : "minprice",price);
            jaddnum(json,"volume",volume);
            jaddstr(json,"BTC",myinfo->myaddr.BTC);
            jaddnum(json,"minperc",jdouble(argjson,"minperc"));
            printf("trade dir.%d (%s/%s) %.6f vol %.8f\n",dir,base,"BTC",price,volume);
            if ( (str= instantdex_createaccept(myinfo,&ap,exchange,base,"BTC",price,volume,-dir,dir > 0 ? "BTC" : base,INSTANTDEX_OFFERDURATION,myinfo->myaddr.nxt64bits,jdouble(argjson,"minperc"))) != 0 && ap != 0 )
            {
                retstr = instantdex_checkoffer(myinfo,&added,&txid,exchange,ap,json);
                free(str);
                if ( added == 0 )
                    free(ap);
            } else printf("null return queueaccept\n");
            if ( retstrp != 0 )
                *retstrp = retstr;
        }
    }
    return(txid);
}

char *ORDERSTATUS(struct exchange_info *exchange,uint64_t orderid,cJSON *argjson)
{
    struct instantdex_accept *ap; struct bitcoin_swapinfo *swap; cJSON *retjson;
    retjson = cJSON_CreateObject();
    struct supernet_info *myinfo;// = SuperNET_accountfind(argjson);
    myinfo = SuperNET_MYINFO(0);//SuperNET_accountfind(argjson);
    if ( (swap= instantdex_statemachinefind(myinfo,exchange,orderid)) != 0 )
        jadd(retjson,"result",instantdex_statemachinejson(swap));
    else if ( (ap= instantdex_offerfind(myinfo,exchange,0,0,orderid,"*","*",0)) != 0 )
        jadd(retjson,"result",instantdex_acceptjson(ap));
    else if ( (swap= instantdex_historyfind(myinfo,exchange,orderid)) != 0 )
        jadd(retjson,"result",instantdex_historyjson(swap));
    else jaddstr(retjson,"error","couldnt find orderid");
    return(jprint(retjson,1));
}

char *CANCELORDER(struct exchange_info *exchange,uint64_t orderid,cJSON *argjson)
{
    struct instantdex_accept *ap = 0; cJSON *retjson; struct bitcoin_swapinfo *swap=0;
    struct supernet_info *myinfo;// = SuperNET_accountfind(argjson);
    myinfo = SuperNET_MYINFO(0);//SuperNET_accountfind(argjson);
    retjson = cJSON_CreateObject();
    if ( (ap= instantdex_offerfind(myinfo,exchange,0,0,orderid,"*","*",0)) != 0 )
    {
        ap->dead = (uint32_t)time(NULL);
        jadd(retjson,"orderid",instantdex_acceptjson(ap));
        jaddstr(retjson,"result","killed orderid, but might have pending");
    }
    else if ( (swap= instantdex_statemachinefind(myinfo,exchange,orderid)) != 0 )
    {
        jadd(retjson,"orderid",instantdex_statemachinejson(swap));
        jaddstr(retjson,"result","killed statemachine orderid, but might have pending");
    }
    return(jprint(retjson,1));
}

char *OPENORDERS(struct exchange_info *exchange,cJSON *argjson)
{
    cJSON *retjson,*bids,*asks; struct supernet_info *myinfo;// = SuperNET_accountfind(argjson);
    myinfo = SuperNET_MYINFO(0);//SuperNET_accountfind(argjson);
    bids = cJSON_CreateArray();
    asks = cJSON_CreateArray();
    instantdex_offerfind(myinfo,exchange,bids,asks,0,"*","*",0);
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"result","success");
    jadd(retjson,"bids",bids);
    jadd(retjson,"asks",asks);
    return(jprint(retjson,1));
}

char *TRADEHISTORY(struct exchange_info *exchange,cJSON *argjson)
{
    struct bitcoin_swapinfo *swap,*tmp; cJSON *retjson = cJSON_CreateArray();
    portable_mutex_lock(&exchange->mutexH);
    DL_FOREACH_SAFE(exchange->history,swap,tmp)
    {
        jaddi(retjson,instantdex_historyjson(swap));
    }
    portable_mutex_unlock(&exchange->mutexH);
    return(jprint(retjson,1));
}

char *WITHDRAW(struct exchange_info *exchange,char *base,double amount,char *destaddr,cJSON *argjson)
{
    //struct supernet_info *myinfo = SuperNET_accountfind(argjson);
    // invoke conversion or transfer!
    return(clonestr("{\"error\":\"what does it mean to withdraw bitcoins that are in your wallet\"}"));
}

struct exchange_funcs bitcoin_funcs = EXCHANGE_FUNCS(bitcoin,EXCHANGE_NAME);

#include "exchange_undefs.h"

