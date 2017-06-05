
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
//  LP_utxos.c
//  marketmaker
//

int32_t LP_ismine(struct LP_utxoinfo *utxo)
{
    if ( strcmp(utxo->ipaddr,"127.0.0.1") == 0 )
        return(1);
    else if ( LP_mypeer == 0 )
        return(0);
    else if ( strcmp(utxo->ipaddr,LP_mypeer->ipaddr) == 0 && utxo->port == LP_mypeer->port )\
        return(1);
    else return(0);
}

int32_t LP_isunspent(struct LP_utxoinfo *utxo)
{
    if ( utxo->spentflag == 0 && utxo->swappending == 0 )
        return(1);
    else return(0);
}

struct LP_utxoinfo *LP_utxofind(bits256 txid,int32_t vout)
{
    struct LP_utxoinfo *utxo=0; uint8_t key[sizeof(txid) + sizeof(vout)];
    memcpy(key,txid.bytes,sizeof(txid));
    memcpy(&key[sizeof(txid)],&vout,sizeof(vout));
    portable_mutex_lock(&LP_utxomutex);
    HASH_FIND(hh,LP_utxoinfos,key,sizeof(key),utxo);
    portable_mutex_unlock(&LP_utxomutex);
    return(utxo);
}

cJSON *LP_inventoryjson(cJSON *item,struct LP_utxoinfo *utxo)
{
    jaddstr(item,"coin",utxo->coin);
    jaddnum(item,"now",time(NULL));
    jaddstr(item,"address",utxo->coinaddr);
    jaddbits256(item,"txid",utxo->txid);
    jaddnum(item,"vout",utxo->vout);
    jadd64bits(item,"value",utxo->value);
    jadd64bits(item,"satoshis",utxo->satoshis);
    jaddbits256(item,"txid2",utxo->txid2);
    jaddnum(item,"vout2",utxo->vout2);
    jadd64bits(item,"value2",utxo->value2);
    if ( utxo->swappending != 0 )
        jaddnum(item,"pending",utxo->swappending);
    if ( bits256_nonz(utxo->otherpubkey) != 0 )
        jaddbits256(item,"desthash",utxo->otherpubkey);
    if ( utxo->pair >= 0 )
        jaddnum(item,"socket",utxo->pair);
    if ( utxo->swap != 0 )
        jaddstr(item,"swap","in progress");
    if ( utxo->spentflag != 0 )
        jaddnum(item,"spent",utxo->spentflag);
    return(item);
}

cJSON *LP_utxojson(struct LP_utxoinfo *utxo)
{
    cJSON *item = cJSON_CreateObject();
    item = LP_inventoryjson(item,utxo);
    jaddstr(item,"ipaddr",utxo->ipaddr);
    jaddnum(item,"port",utxo->port);
    jaddnum(item,"profit",utxo->profitmargin);
    jaddstr(item,"base",utxo->coin);
    jaddstr(item,"script",utxo->spendscript);
    return(item);
}

char *LP_utxos(struct LP_peerinfo *mypeer,char *coin,int32_t lastn)
{
    int32_t i,firsti; struct LP_utxoinfo *utxo,*tmp; cJSON *utxosjson = cJSON_CreateArray();
    i = 0;
    if ( lastn >= mypeer->numutxos )
        firsti = -1;
    else firsti = (mypeer->numutxos - lastn);
    HASH_ITER(hh,LP_utxoinfos,utxo,tmp)
    {
        if ( i++ < firsti )
            continue;
        if ( (coin == 0 || coin[0] == 0 || strcmp(coin,utxo->coin) == 0) )//&& LP_ismine(utxo) != 0 )
        {
            jaddi(utxosjson,LP_utxojson(utxo));
        }
    }
    return(jprint(utxosjson,1));
}

void LP_spentnotify(struct LP_utxoinfo *utxo,int32_t selector)
{
    cJSON *argjson;
    utxo->spentflag = (uint32_t)time(NULL);
    if ( LP_mypubsock >= 0 )
    {
        argjson = cJSON_CreateObject();
        jaddstr(argjson,"method","checktxid");
        jaddbits256(argjson,"txid",utxo->txid);
        jaddnum(argjson,"vout",utxo->vout);
        if ( selector != 0 )
        {
            jaddbits256(argjson,"checktxid",utxo->txid2);
            jaddnum(argjson,"checkvout",utxo->vout2);
        }
        LP_send(LP_mypubsock,jprint(argjson,1),1);
    }
}

char *LP_spentcheck(cJSON *argjson)
{
    bits256 txid,checktxid; int32_t vout,checkvout; struct LP_utxoinfo *utxo;
    txid = jbits256(argjson,"txid");
    vout = jint(argjson,"vout");
    if ( (utxo= LP_utxofind(txid,vout)) != 0 )
    {
        if ( jobj(argjson,"check") == 0 )
            checktxid = txid, checkvout = vout;
        else
        {
            checktxid = jbits256(argjson,"checktxid");
            checkvout = jint(argjson,"checkvout");
        }
        if ( LP_txvalue(utxo->coin,checktxid,checkvout) == 0 )
        {
            utxo->spentflag = (uint32_t)time(NULL);
            //printf("indeed txid was spent\n");
            return(clonestr("{\"result\":\"marked as spent\"}"));
        } else return(clonestr("{\"error\":\"txid is still unspent?\"}"));
    } else return(clonestr("{\"error\":\"cant find txid to check spent status\"}"));
}

int32_t LP_iseligible(char *coin,bits256 txid,int32_t vout,uint64_t satoshis,bits256 txid2,int32_t vout2)
{
    uint64_t val,val2;
    if ( (val= LP_txvalue(coin,txid,vout)) >= satoshis )
    {
        if ( (val2= LP_txvalue(coin,txid2,vout2)) >= LP_DEPOSITSATOSHIS(satoshis) )
        {
            //printf("val %.8f and val2 %.8f vs %.8f\n",dstr(val),dstr(val2),dstr(satoshis));
            return(1);
        } else printf("mismatched %s txid value2 %.8f < %.8f\n",coin,dstr(val2),dstr(LP_DEPOSITSATOSHIS(satoshis)));
    } else printf("mismatched %s txid value %.8f < %.8f\n",coin,dstr(val),dstr(satoshis));
    return(0);
}

struct LP_utxoinfo *LP_addutxo(int32_t amclient,struct LP_peerinfo *mypeer,int32_t mypubsock,char *coin,bits256 txid,int32_t vout,int64_t value,bits256 txid2,int32_t vout2,int64_t value2,char *spendscript,char *coinaddr,char *ipaddr,uint16_t port,double profitmargin)
{
    uint64_t tmpsatoshis; struct LP_utxoinfo *utxo = 0;
    if ( coin == 0 || coin[0] == 0 || spendscript == 0 || spendscript[0] == 0 || coinaddr == 0 || coinaddr[0] == 0 || bits256_nonz(txid) == 0 || bits256_nonz(txid2) == 0 || vout < 0 || vout2 < 0 || value <= 0 || value2 <= 0 )
    {
        printf("malformed addutxo %d %d %d %d %d %d %d %d %d\n", coin == 0,spendscript == 0,coinaddr == 0,bits256_nonz(txid) == 0,bits256_nonz(txid2) == 0,vout < 0,vout2 < 0,value <= 0,value2 <= 0);
        return(0);
    }
    if ( LP_iseligible(coin,txid,vout,value,txid2,vout2) <= 0 )
    {
        printf("LP_addutxo got spent txid\n");
        return(0);
    }
    if ( IAMCLIENT == 0 && strcmp(ipaddr,"127.0.0.1") == 0 )
    {
        printf("LP node got localhost utxo\n");
        return(0);
    }
    if ( IAMCLIENT == 0 && value2 < 9 * (value >> 3) + 100000 )
        tmpsatoshis = (((value2-100000) / 9) << 3);
    else tmpsatoshis = value;
    if ( (utxo= LP_utxofind(txid,vout)) != 0 )
    {
        //printf("%.8f %.8f %.8f vs utxo.(%.8f %.8f %.8f)\n",dstr(value),dstr(value2),dstr(tmpsatoshis),dstr(utxo->value),dstr(utxo->value2),dstr(utxo->satoshis));
        if ( bits256_cmp(txid,utxo->txid) != 0 || bits256_cmp(txid2,utxo->txid2) != 0 || vout != utxo->vout || value != utxo->value || tmpsatoshis != utxo->satoshis || vout2 != utxo->vout2 || value2 != utxo->value2 || strcmp(coin,utxo->coin) != 0 || strcmp(spendscript,utxo->spendscript) != 0 || strcmp(coinaddr,utxo->coinaddr) != 0 || strcmp(ipaddr,utxo->ipaddr) != 0 || port != utxo->port )
        {
            utxo->errors++;
            char str[65],str2[65]; printf("error on subsequent utxo add.(%s v %s) %d %d %d %d %d %d %d %d %d %d %d %d\n",bits256_str(str,txid),bits256_str(str2,utxo->txid),bits256_cmp(txid,utxo->txid) != 0,bits256_cmp(txid2,utxo->txid2) != 0,vout != utxo->vout,tmpsatoshis != utxo->satoshis,vout2 != utxo->vout2,value2 != utxo->value2,strcmp(coin,utxo->coin) != 0,strcmp(spendscript,utxo->spendscript) != 0,strcmp(coinaddr,utxo->coinaddr) != 0,strcmp(ipaddr,utxo->ipaddr) != 0,port != utxo->port,value != utxo->value);
        }
        else if ( profitmargin != 0. )
            utxo->profitmargin = profitmargin;
    }
    else
    {
        utxo = calloc(1,sizeof(*utxo));
        utxo->pair = -1;
        utxo->profitmargin = profitmargin;
        strcpy(utxo->ipaddr,ipaddr);
        utxo->port = port;
        safecopy(utxo->coin,coin,sizeof(utxo->coin));
        safecopy(utxo->coinaddr,coinaddr,sizeof(utxo->coinaddr));
        safecopy(utxo->spendscript,spendscript,sizeof(utxo->spendscript));
        utxo->txid = txid;
        utxo->vout = vout;
        utxo->value = value;
        utxo->satoshis = tmpsatoshis;
        utxo->txid2 = txid2;
        utxo->vout2 = vout2;
        utxo->value2 = value2;
        memcpy(utxo->key,txid.bytes,sizeof(txid));
        memcpy(&utxo->key[sizeof(txid)],&vout,sizeof(vout));
        portable_mutex_lock(&LP_utxomutex);
        HASH_ADD_KEYPTR(hh,LP_utxoinfos,utxo->key,sizeof(utxo->key),utxo);
        if ( mypeer != 0 )
            mypeer->numutxos++;
        portable_mutex_unlock(&LP_utxomutex);
        if ( mypubsock >= 0 )
            LP_send(mypubsock,jprint(LP_utxojson(utxo),1),1);
        char str[65],str2[65]; printf("amclient.%d %s:%u %s LP_addutxo.(%.8f %.8f) numutxos.%d %s %s\n",IAMCLIENT,ipaddr,port,utxo->coin,dstr(value),dstr(value2),mypeer!=0?mypeer->numutxos:0,bits256_str(str,utxo->txid),bits256_str(str2,txid2));
    }
    return(utxo);
}

int32_t LP_utxosparse(int32_t amclient,struct LP_peerinfo *mypeer,int32_t mypubsock,char *destipaddr,uint16_t destport,char *retstr,uint32_t now)
{
    struct LP_peerinfo *peer,*destpeer; uint32_t argipbits; char *argipaddr; uint16_t argport,pushport,subport; cJSON *array,*item; int32_t i,n=0; bits256 txid; struct LP_utxoinfo *utxo;
    if ( amclient != 0 )
    {
        printf("LP_utxosparse not for clientside\n");
        return(-1);
    }
    if ( (array= cJSON_Parse(retstr)) != 0 )
    {
        if ( (n= cJSON_GetArraySize(array)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                item = jitem(array,i);
                if ( (argipaddr= jstr(item,"ipaddr")) != 0 && (argport= juint(item,"port")) != 0 )
                {
                    if ( (pushport= juint(item,"push")) == 0 )
                        pushport = argport + 1;
                    if ( (subport= juint(item,"sub")) == 0 )
                        subport = argport + 2;
                    argipbits = (uint32_t)calc_ipbits(argipaddr);
                    if ( (peer= LP_peerfind(argipbits,argport)) == 0 )
                        peer = LP_addpeer(amclient,mypeer,mypubsock,argipaddr,argport,pushport,subport,jdouble(item,"profit"),jint(item,"numpeers"),jint(item,"numutxos"));
                    if ( jobj(item,"txid") != 0 )
                    {
                        txid = jbits256(item,"txid");
                        //printf("parse.(%s)\n",jprint(item,0));
                        utxo = LP_addutxo(amclient,mypeer,mypubsock,jstr(item,"coin"),txid,jint(item,"vout"),j64bits(item,"value"),jbits256(item,"txid2"),jint(item,"vout2"),j64bits(item,"value2"),jstr(item,"script"),jstr(item,"address"),argipaddr,argport,jdouble(item,"profit"));
                        if ( utxo != 0 )
                            utxo->lasttime = now;
                    }
                } // else printf("skip.(%s)\n",jprint(item,0));
            }
            if ( (destpeer= LP_peerfind((uint32_t)calc_ipbits(destipaddr),destport)) != 0 )
            {
                destpeer->numutxos = n;
            }
        }
        free_json(array);
    }
    return(n);
}

void LP_utxosquery(int32_t amclient,struct LP_peerinfo *mypeer,int32_t mypubsock,char *destipaddr,uint16_t destport,char *coin,int32_t lastn,char *myipaddr,uint16_t myport,double myprofit)
{
    char *retstr; struct LP_peerinfo *peer; int32_t i,firsti; uint32_t now;
    if ( amclient != 0 )
    {
        printf("LP_utxosquery not for clientside\n");
        return;
    }
    peer = LP_peerfind((uint32_t)calc_ipbits(destipaddr),destport);
    if ( mypeer == 0 ) //(peer != 0 && peer->errors > 0) || 
        return;
    if ( coin == 0 )
        coin = "";
    if ( (retstr= issue_LP_getutxos(destipaddr,destport,coin,lastn,myipaddr,myport,myprofit,mypeer->numpeers,mypeer->numutxos)) != 0 )
    {
        now = (uint32_t)time(NULL);
        LP_utxosparse(amclient,mypeer,mypubsock,destipaddr,destport,retstr,now);
        free(retstr);
        i = 0;
        if ( lastn >= mypeer->numutxos )
            firsti = -1;
        else firsti = (mypeer->numutxos - lastn);
        /*HASH_ITER(hh,LP_utxoinfos,utxo,tmp)
        {
            if ( i++ < firsti )
                continue;
            if ( utxo->lasttime != now && strcmp(utxo->ipaddr,"127.0.0.1") != 0 )
            {
                char str[65]; printf("{%s:%u %s} ",utxo->ipaddr,utxo->port,bits256_str(str,utxo->txid));
                flag++;
                if ( (retstr= issue_LP_notifyutxo(destipaddr,destport,utxo)) != 0 )
                    free(retstr);
            }
        }
        if ( flag != 0 )
            printf(" <- missing utxos\n");*/
    } else if ( peer != 0 )
        peer->errors++;
}

char *LP_inventory(char *symbol)
{
    struct LP_utxoinfo *utxo,*tmp; char *myipaddr; cJSON *array = cJSON_CreateArray();
    if ( LP_mypeer != 0 )
        myipaddr = LP_mypeer->ipaddr;
    else myipaddr = "127.0.0.1";
    HASH_ITER(hh,LP_utxoinfos,utxo,tmp)
    {
        if ( LP_isunspent(utxo) != 0 && strcmp(symbol,utxo->coin) == 0 && (IAMCLIENT != 0 || LP_ismine(utxo) != 0) )
            jaddi(array,LP_inventoryjson(cJSON_CreateObject(),utxo));
    }
    return(jprint(array,1));
}

int32_t LP_maxvalue(uint64_t *values,int32_t n)
{
    int32_t i,maxi = -1; uint64_t maxval = 0;
    for (i=0; i<n; i++)
        if ( values[i] > maxval )
        {
            maxi = i;
            maxval = values[i];
        }
    return(maxi);
}

int32_t LP_nearestvalue(uint64_t *values,int32_t n,uint64_t targetval)
{
    int32_t i,mini = -1; int64_t dist; uint64_t mindist = (1 << 31);
    for (i=0; i<n; i++)
    {
        dist = (values[i] - targetval);
        if ( dist < 0 && -dist < values[i]/10 )
            dist = -dist;
        if ( dist >= 0 && dist < mindist )
        {
            mini = i;
            mindist = dist;
        }
    }
    return(mini);
}

uint64_t LP_privkey_init(struct LP_peerinfo *mypeer,int32_t mypubsock,char *symbol,char *passphrase,char *wifstr,int32_t amclient)
{
    static uint32_t counter;
    char *script; struct LP_utxoinfo *utxo; cJSON *array,*item,*retjson; bits256 userpass,userpub,txid,deposittxid; int32_t used,i,n,vout,depositvout; uint64_t *values,satoshis,depositval,targetval,value,total = 0; bits256 privkey,pubkey; uint8_t pubkey33[33],tmptype,rmd160[20]; struct iguana_info *coin = LP_coinfind(symbol);
    if ( coin == 0 )
    {
        printf("cant add privkey for %s, coin not active\n",symbol);
        return(0);
    }
    if ( passphrase != 0 )
        conv_NXTpassword(privkey.bytes,pubkey.bytes,(uint8_t *)passphrase,(int32_t)strlen(passphrase));
    else privkey = iguana_wif2privkey(wifstr);
    iguana_priv2pub(pubkey33,coin->smartaddr,privkey,coin->pubtype);
    if ( counter == 0 )
    {
        char tmpstr[128];
        counter++;
        bitcoin_priv2wif(USERPASS_WIFSTR,privkey,188);
        bitcoin_priv2wif(tmpstr,privkey,coin->wiftype);
        conv_NXTpassword(userpass.bytes,pubkey.bytes,(uint8_t *)tmpstr,(int32_t)strlen(tmpstr));
        userpub = curve25519(userpass,curve25519_basepoint9());
        printf("userpass.(%s)\n",bits256_str(USERPASS,userpub));
        printf("%s (%s) %d wif.(%s) (%s)\n",symbol,coin->smartaddr,coin->pubtype,tmpstr,passphrase);
        if ( (retjson= LP_importprivkey(coin->symbol,tmpstr,coin->smartaddr,-1)) != 0 )
            printf("importprivkey -> (%s)\n",jprint(retjson,1));
    }
    bitcoin_addr2rmd160(&tmptype,rmd160,coin->smartaddr);
    LP_privkeyadd(privkey,rmd160);
    if ( (array= LP_listunspent(symbol,coin->smartaddr)) != 0 )
    {
        if ( is_cJSON_Array(array) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
        {
            values = calloc(n,sizeof(*values));
            for (i=0; i<n; i++)
            {
                item = jitem(array,i);
                satoshis = SATOSHIDEN * jdouble(item,"amount");
                values[i] = satoshis;
                //printf("%.8f ",dstr(satoshis));
            }
            //printf("array.%d\n",n);
            used = 0;
            while ( used < n )
            {
                if ( (i= LP_maxvalue(values,n)) >= 0 )
                {
                    item = jitem(array,i);
                    deposittxid = jbits256(item,"txid");
                    depositvout = juint(item,"vout");
                    script = jstr(item,"scriptPubKey");
                    depositval = values[i];
                    values[i] = 0, used++;
                    if ( amclient != 0 )
                        targetval = (depositval / 776) + 100000;
                    else targetval = (depositval / 9) * 8 + 100000;
                    //printf("i.%d %.8f target %.8f\n",i,dstr(depositval),dstr(targetval));
                    if ( (i= LP_nearestvalue(values,n,targetval)) >= 0 )
                    {
                        item = jitem(array,i);
                        txid = jbits256(item,"txid");
                        vout = juint(item,"vout");
                        if ( jstr(item,"scriptPubKey") != 0 && strcmp(script,jstr(item,"scriptPubKey")) == 0 )
                        {
                            value = values[i];
                            values[i] = 0, used++;
                            if ( amclient == 0 )
                            {
                                if ( (utxo= LP_addutxo(amclient,mypeer,mypubsock,symbol,txid,vout,value,deposittxid,depositvout,depositval,script,coin->smartaddr,LP_peerinfos[0].ipaddr,LP_peerinfos[0].port,LP_peerinfos[0].profitmargin)) != 0 )
                                    utxo->mypub = curve25519(privkey,curve25519_basepoint9());
                            }
                            else
                            {
                                if ( (utxo= LP_addutxo(amclient,mypeer,mypubsock,symbol,deposittxid,depositvout,depositval,txid,vout,value,script,coin->smartaddr,"127.0.0.1",0,0)) != 0 )
                                    utxo->mypub = curve25519(privkey,curve25519_basepoint9());
                            }
                            total += value;
                        }
                    }
                } else break;
            }
            free(values);
        }
        free_json(array);
    }
    return(total);
}

void LP_privkey_updates(struct LP_peerinfo *mypeer,int32_t pubsock,char *passphrase,int32_t amclient)
{
    int32_t i;
    for (i=0; i<sizeof(activecoins)/sizeof(*activecoins); i++)
        LP_privkey_init(mypeer,pubsock,activecoins[i],passphrase,"",amclient);
}


