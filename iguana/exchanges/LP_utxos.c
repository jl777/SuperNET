
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
    if ( utxo != 0 && bits256_cmp(utxo->pubkey,LP_mypubkey) == 0 )
        return(1);
    else return(0);
}

int32_t LP_isavailable(struct LP_utxoinfo *utxo)
{
    if ( time(NULL) > utxo->T.swappending )
        utxo->T.swappending = 0;
    if ( utxo != 0 && utxo->T.swappending == 0 && utxo->S.swap == 0 )
        return(1);
    else return(0);
}

int32_t LP_isunspent(struct LP_utxoinfo *utxo)
{
    if ( utxo != 0 && utxo->T.spentflag == 0 && LP_isavailable(utxo) > 0 )
        return(1);
    else return(0);
}

void LP_utxosetkey(uint8_t *key,bits256 txid,int32_t vout)
{
    memcpy(key,txid.bytes,sizeof(txid));
    memcpy(&key[sizeof(txid)],&vout,sizeof(vout));
}

struct LP_utxoinfo *_LP_utxofind(int32_t iambob,bits256 txid,int32_t vout)
{
    struct LP_utxoinfo *utxo=0; uint8_t key[sizeof(txid) + sizeof(vout)];
    LP_utxosetkey(key,txid,vout);
    HASH_FIND(hh,LP_utxoinfos[iambob],key,sizeof(key),utxo);
    return(utxo);
}

struct LP_utxoinfo *_LP_utxo2find(int32_t iambob,bits256 txid2,int32_t vout2)
{
    struct LP_utxoinfo *utxo=0; uint8_t key2[sizeof(txid2) + sizeof(vout2)];
    LP_utxosetkey(key2,txid2,vout2);
    HASH_FIND(hh2,LP_utxoinfos2[iambob],key2,sizeof(key2),utxo);
    return(utxo);
}

struct LP_utxoinfo *LP_utxofind(int32_t iambob,bits256 txid,int32_t vout)
{
    struct LP_utxoinfo *utxo=0;
    portable_mutex_lock(&LP_utxomutex);
    utxo = _LP_utxofind(iambob,txid,vout);
    portable_mutex_unlock(&LP_utxomutex);
    return(utxo);
}

struct LP_utxoinfo *LP_utxopairfind(int32_t iambob,bits256 txid,int32_t vout,bits256 txid2,int32_t vout2)
{
    struct LP_utxoinfo *utxo=0; struct _LP_utxoinfo u;
    if ( (utxo= LP_utxofind(iambob,txid,vout)) != 0 )
    {
        u = (iambob != 0) ? utxo->deposit : utxo->fee;
        if (vout2 == u.vout && bits256_cmp(u.txid,txid2) == 0 )
            return(utxo);
    }
    return(0);
}

struct LP_utxoinfo *LP_utxo2find(int32_t iambob,bits256 txid2,int32_t vout2)
{
    struct LP_utxoinfo *utxo=0;
    portable_mutex_lock(&LP_utxomutex);
    utxo = _LP_utxo2find(iambob,txid2,vout2);
    portable_mutex_unlock(&LP_utxomutex);
    return(utxo);
}

struct LP_utxoinfo *LP_utxofinds(int32_t iambob,bits256 txid,int32_t vout,bits256 txid2,int32_t vout2)
{
    struct LP_utxoinfo *utxo;
    if ( (utxo= LP_utxofind(iambob,txid,vout)) != 0 || (utxo= LP_utxofind(iambob,txid2,vout2)) != 0 || (utxo= LP_utxo2find(iambob,txid,vout)) != 0 || (utxo= LP_utxo2find(iambob,txid2,vout2)) != 0 )
        return(utxo);
    else return(0);
}

int32_t LP_utxoaddptrs(struct LP_utxoinfo *ptrs[],int32_t n,struct LP_utxoinfo *utxo)
{
    int32_t i;
    for (i=0; i<n; i++)
        if ( ptrs[i] == utxo )
            return(n);
    ptrs[n++] = utxo;
    return(n);
}

int32_t LP_utxocollisions(struct LP_utxoinfo *ptrs[],struct LP_utxoinfo *refutxo)
{
    int32_t iambob,n = 0; struct LP_utxoinfo *utxo; struct _LP_utxoinfo u;
    if ( refutxo == 0 )
        return(0);
    portable_mutex_lock(&LP_utxomutex);
    for (iambob=0; iambob<=1; iambob++)
    {
        if ( (utxo= _LP_utxofind(iambob,refutxo->payment.txid,refutxo->payment.vout)) != 0 && utxo != refutxo )
            n = LP_utxoaddptrs(ptrs,n,utxo);
        if ( (utxo= _LP_utxo2find(iambob,refutxo->payment.txid,refutxo->payment.vout)) != 0 && utxo != refutxo )
            n = LP_utxoaddptrs(ptrs,n,utxo);
        u = (refutxo->iambob != 0) ? refutxo->deposit : refutxo->fee;
        if ( (utxo= _LP_utxofind(iambob,u.txid,u.vout)) != 0 && utxo != refutxo )
            n = LP_utxoaddptrs(ptrs,n,utxo);
        if ( (utxo= _LP_utxo2find(iambob,u.txid,u.vout)) != 0 && utxo != refutxo )
            n = LP_utxoaddptrs(ptrs,n,utxo);
    }
    portable_mutex_unlock(&LP_utxomutex);
    if ( 0 && n > 0 )
        printf("LP_utxocollisions n.%d\n",n);
    return(n);
}

int32_t _LP_availableset(struct LP_utxoinfo *utxo)
{
    int32_t flag = 0;
    if ( utxo != 0 )
    {
        if ( bits256_nonz(utxo->S.otherpubkey) != 0 )
            flag = 1, memset(&utxo->S.otherpubkey,0,sizeof(utxo->S.otherpubkey));
        if ( utxo->S.swap != 0 )
            flag = 1, utxo->S.swap = 0;
        if ( utxo->T.swappending != 0 )
            flag = 1, utxo->T.swappending = 0;
        return(flag);
    }
    return(0);
}

void _LP_unavailableset(struct LP_utxoinfo *utxo,bits256 otherpubkey)
{
    if ( utxo != 0 )
    {
        utxo->T.swappending = (uint32_t)(time(NULL) + LP_RESERVETIME);
        utxo->S.otherpubkey = otherpubkey;
    }
}

void LP_unavailableset(struct LP_utxoinfo *utxo,bits256 otherpubkey)
{
    struct LP_utxoinfo *ptrs[8]; int32_t i,n; struct _LP_utxoinfo u;
    memset(ptrs,0,sizeof(ptrs));
    if ( (n= LP_utxocollisions(ptrs,utxo)) > 0 )
    {
        for (i=0; i<n; i++)
            _LP_unavailableset(ptrs[i],otherpubkey);
    }
    u = (utxo->iambob != 0) ? utxo->deposit : utxo->fee;
    char str[65],str2[65]; printf("UTXO.[%d] RESERVED %s/v%d %s/v%d collisions.%d\n",utxo->iambob,bits256_str(str,utxo->payment.txid),utxo->payment.vout,bits256_str(str2,u.txid),u.vout,n);
    _LP_unavailableset(utxo,otherpubkey);
}

void LP_availableset(struct LP_utxoinfo *utxo)
{
    struct LP_utxoinfo *ptrs[8]; int32_t i,n,count = 0; struct _LP_utxoinfo u;
    if ( utxo != 0 )
    {
        memset(ptrs,0,sizeof(ptrs));
        if ( (n= LP_utxocollisions(ptrs,utxo)) > 0 )
        {
            for (i=0; i<n; i++)
                count += _LP_availableset(ptrs[i]);
        }
        count += _LP_availableset(utxo);
        if ( count > 0 )
        {
            u = (utxo->iambob != 0) ? utxo->deposit : utxo->fee;
            char str[65],str2[65]; printf("UTXO.[%d] AVAIL %s/v%d %s/v%d collisions.%d\n",utxo->iambob,bits256_str(str,utxo->payment.txid),utxo->payment.vout,bits256_str(str2,u.txid),u.vout,n);
        }
    }
}

int32_t LP_utxopurge(int32_t allutxos)
{
    char str[65]; struct LP_utxoinfo *utxo,*tmp; int32_t iambob,n = 0;
    printf("LP_utxopurge mypub.(%s)\n",bits256_str(str,LP_mypubkey));
    portable_mutex_lock(&LP_utxomutex);
    for (iambob=0; iambob<=1; iambob++)
    {
        HASH_ITER(hh,LP_utxoinfos[iambob],utxo,tmp)
        {
            if ( LP_isavailable(utxo) > 0 )
            {
                if ( allutxos != 0 || LP_ismine(utxo) > 0 )
                {
                    printf("iambob.%d delete.(%s)\n",iambob,bits256_str(str,utxo->payment.txid));
                    HASH_DELETE(hh,LP_utxoinfos[iambob],utxo);
                    //free(utxo); let the LP_utxoinfos2 free the utxo, should be 1:1
                } else n++;
            } else n++;
        }
        HASH_ITER(hh,LP_utxoinfos2[iambob],utxo,tmp)
        {
            if ( LP_isavailable(utxo) > 0 )
            {
                if ( allutxos != 0 || LP_ismine(utxo) > 0 )
                {
                    printf("iambob.%d delete2.(%s)\n",iambob,bits256_str(str,utxo->payment.txid));
                    HASH_DELETE(hh2,LP_utxoinfos2[iambob],utxo);
                    free(utxo);
                } else n++;
            } else n++;
        }
    }
    portable_mutex_unlock(&LP_utxomutex);
    return(n);
}

cJSON *LP_inventoryjson(cJSON *item,struct LP_utxoinfo *utxo)
{
    struct _LP_utxoinfo u;
    jaddstr(item,"method","notified");
    if ( utxo == 0 )
        return(item);
    if ( utxo->gui[0] != 0 )
        jaddstr(item,"gui",utxo->gui);
    jaddstr(item,"coin",utxo->coin);
    jaddnum(item,"now",time(NULL));
    jaddnum(item,"iambob",utxo->iambob);
    jaddstr(item,"address",utxo->coinaddr);
    jaddbits256(item,"txid",utxo->payment.txid);
    jaddnum(item,"vout",utxo->payment.vout);
    jadd64bits(item,"value",utxo->payment.value);
    jadd64bits(item,"satoshis",utxo->S.satoshis);
    u = (utxo->iambob != 0) ? utxo->deposit : utxo->fee;
    if ( bits256_nonz(u.txid) != 0 )
    {
        jaddbits256(item,"txid2",u.txid);
        jaddnum(item,"vout2",u.vout);
        jadd64bits(item,"value2",u.value);
    }
    if ( utxo->T.swappending != 0 )
        jaddnum(item,"pending",utxo->T.swappending);
    if ( utxo->iambob != 0 )
    {
        jaddbits256(item,"srchash",LP_mypubkey);
        if ( bits256_nonz(utxo->S.otherpubkey) != 0 )
            jaddbits256(item,"desthash",utxo->S.otherpubkey);
    }
    else
    {
        jaddbits256(item,"desthash",LP_mypubkey);
        if ( bits256_nonz(utxo->S.otherpubkey) != 0 )
            jaddbits256(item,"srchash",utxo->S.otherpubkey);
    }
    if ( utxo->S.swap != 0 )
        jaddstr(item,"swap","in progress");
    if ( utxo->T.spentflag != 0 )
        jaddnum(item,"spent",utxo->T.spentflag);
    return(item);
}

cJSON *LP_utxojson(struct LP_utxoinfo *utxo)
{
    cJSON *item = cJSON_CreateObject();
    item = LP_inventoryjson(item,utxo);
    jaddbits256(item,"pubkey",utxo->pubkey);
    jaddnum(item,"profit",utxo->S.profitmargin);
    jaddstr(item,"base",utxo->coin);
    jaddstr(item,"script",utxo->spendscript);
    return(item);
}

int32_t LP_iseligible(uint64_t *valp,uint64_t *val2p,int32_t iambob,char *symbol,bits256 txid,int32_t vout,uint64_t satoshis,bits256 txid2,int32_t vout2)
{
    uint64_t val,val2=0,threshold=0; int32_t iter; char destaddr[64],destaddr2[64]; struct LP_utxoinfo *utxo;
    destaddr[0] = destaddr2[0] = 0;
    if ( (val= LP_txvalue(destaddr,symbol,txid,vout)) >= satoshis )
    {
        threshold = (iambob != 0) ? LP_DEPOSITSATOSHIS(satoshis) : LP_DEXFEE(satoshis);
        if ( (val2= LP_txvalue(destaddr2,symbol,txid2,vout2)) >= threshold )
        {
            if ( strcmp(destaddr,destaddr2) != 0 )
                printf("mismatched %s destaddr (%s) vs (%s)\n",symbol,destaddr,destaddr2);
            else if ( (iambob == 0 && val2 > val) || (iambob != 0 && val2 <= satoshis) )
                printf("iambob.%d ineligible due to offsides: val %.8f and val2 %.8f vs %.8f diff %lld\n",iambob,dstr(val),dstr(val2),dstr(satoshis),(long long)(val2 - val));
            else
            {
                *valp = val;
                *val2p = val2;
                return(1);
            }
        } // else printf("no val2\n");
    }
    char str[65],str2[65]; printf("spent.%d %s txid or value %.8f < %.8f or val2 %.8f < %.8f, %s/v%d %s/v%d\n",iambob,symbol,dstr(val),dstr(satoshis),dstr(val2),dstr(threshold),bits256_str(str,txid),vout,bits256_str(str2,txid2),vout2);
    for (iter=0; iter<2; iter++)
    {
        if ( (utxo= LP_utxofind(iter,txid,vout)) != 0 )
        {
            //printf("iambob.%d case 00\n",iter);
            if ( utxo->T.spentflag == 0 )
                utxo->T.spentflag = (uint32_t)time(NULL);
        }
        if ( (utxo= LP_utxo2find(iter,txid,vout)) != 0 )
        {
            //printf("iambob.%d case 01\n",iter);
            if ( utxo->T.spentflag == 0 )
                utxo->T.spentflag = (uint32_t)time(NULL);
        }
        if ( (utxo= LP_utxofind(iter,txid2,vout2)) != 0 )
        {
            //printf("iambob.%d case 10\n",iter);
            if ( utxo->T.spentflag == 0 )
                utxo->T.spentflag = (uint32_t)time(NULL);
        }
        if ( (utxo= LP_utxo2find(iter,txid2,vout2)) != 0 )
        {
            //printf("iambob.%d case 11\n",iter);
            if ( utxo->T.spentflag == 0 )
                utxo->T.spentflag = (uint32_t)time(NULL);
        }
    }
    *valp = val;
    *val2p = val2;
    return(0);
}

char *LP_utxos(int32_t iambob,struct LP_peerinfo *mypeer,char *symbol,int32_t lastn)
{
    int32_t i,firsti,n; uint64_t val,val2; struct _LP_utxoinfo u; struct LP_utxoinfo *utxo,*tmp; cJSON *utxosjson = cJSON_CreateArray();
    i = 0;
    n = mypeer != 0 ? mypeer->numutxos : 0;
    if ( lastn <= 0 )
        lastn = LP_PROPAGATION_SLACK * 2;
    if ( lastn >= n )
        firsti = -1;
    else firsti = (lastn - n);
    //printf("LP_utxos iambob.%d symbol.%s firsti.%d lastn.%d\n",iambob,symbol==0?"":symbol,firsti,lastn);
    HASH_ITER(hh,LP_utxoinfos[iambob],utxo,tmp)
    {
        //char str[65]; printf("check %s.%s\n",utxo->coin,bits256_str(str,utxo->payment.txid));
        if ( i++ < firsti )
            continue;
        if ( (symbol == 0 || symbol[0] == 0 || strcmp(symbol,utxo->coin) == 0) && utxo->T.spentflag == 0 )
        {
            u = (iambob != 0) ? utxo->deposit : utxo->fee;
            if ( LP_iseligible(&val,&val2,utxo->iambob,utxo->coin,utxo->payment.txid,utxo->payment.vout,utxo->S.satoshis,u.txid,u.vout) == 0 )
            {
                char str[65]; printf("iambob.%d not eligible (%.8f %.8f) %s %s/v%d\n",iambob,dstr(val),dstr(val2),utxo->coin,bits256_str(str,utxo->payment.txid),utxo->payment.vout);
                continue;
            } else jaddi(utxosjson,LP_utxojson(utxo));
        }
    }
    return(jprint(utxosjson,1));
}

int32_t LP_inventory_prevent(int32_t iambob,bits256 txid,int32_t vout)
{
    struct LP_utxoinfo *utxo;
    if ( (utxo= LP_utxofind(iambob,txid,vout)) != 0 || (utxo= LP_utxo2find(iambob,txid,vout)) != 0 )
    {
        //if ( utxo->T.spentflag != 0 )
        {
            //char str[65]; printf("prevent adding %s/v%d to inventory\n",bits256_str(str,txid),vout);
            return(1);
        }
    }
    return(0);
}

struct LP_utxoinfo *LP_utxo_bestfit(char *symbol,uint64_t destsatoshis)
{
    uint64_t srcvalue,srcvalue2; struct LP_utxoinfo *utxo,*tmp,*bestutxo = 0;
    if ( symbol == 0 || destsatoshis == 0 )
        return(0);
    HASH_ITER(hh,LP_utxoinfos[0],utxo,tmp)
    {
        if ( strcmp(symbol,utxo->coin) != 0 )
            continue;
        //char str[65]; printf("s%u %d [%.8f vs %.8f] check %s.%s avail.%d ismine.%d >= %d\n",utxo->T.spentflag,LP_iseligible(&srcvalue,&srcvalue2,utxo->iambob,symbol,utxo->payment.txid,utxo->payment.vout,utxo->S.satoshis,utxo->fee.txid,utxo->fee.vout),dstr(destsatoshis),dstr(utxo->S.satoshis),utxo->coin,bits256_str(str,utxo->payment.txid),LP_isavailable(utxo) > 0,LP_ismine(utxo) > 0,utxo->S.satoshis >= destsatoshis);
        if ( LP_isavailable(utxo) > 0 && LP_ismine(utxo) > 0 )
        {
            if ( utxo->S.satoshis >= destsatoshis && (bestutxo == 0 || utxo->S.satoshis < bestutxo->S.satoshis) )
            {
                if ( LP_iseligible(&srcvalue,&srcvalue2,utxo->iambob,symbol,utxo->payment.txid,utxo->payment.vout,utxo->S.satoshis,utxo->fee.txid,utxo->fee.vout) == 0 )
                {
                    if ( utxo->T.spentflag == 0 )
                        utxo->T.spentflag = (uint32_t)time(NULL);
                    continue;
                }
                bestutxo = utxo;
            }
        }
    }
    return(bestutxo);
}

void LP_spentnotify(struct LP_utxoinfo *utxo,int32_t selector)
{
    cJSON *argjson; struct _LP_utxoinfo u; char *msg;
    if ( utxo == 0 )
        return;
    utxo->T.spentflag = (uint32_t)time(NULL);
    if ( LP_mypeer != 0 && LP_mypeer->numutxos > 0 )
        LP_mypeer->numutxos--;
    if ( LP_mypubsock >= 0 )
    {
        argjson = cJSON_CreateObject();
        jaddstr(argjson,"method","checktxid");
        jaddbits256(argjson,"txid",utxo->payment.txid);
        jaddnum(argjson,"vout",utxo->payment.vout);
        if ( selector != 0 )
        {
            if ( bits256_nonz(utxo->deposit.txid) != 0 )
                u = utxo->deposit;
            else u = utxo->fee;
            jaddbits256(argjson,"checktxid",u.txid);
            jaddnum(argjson,"checkvout",u.vout);
        }
        msg = jprint(argjson,1);
        LP_send(LP_mypubsock,msg,(int32_t)strlen(msg)+1,1);
    }
}

char *LP_spentcheck(cJSON *argjson)
{
    bits256 txid,checktxid; int32_t vout,checkvout; struct LP_utxoinfo *utxo; int32_t iambob,retval = 0;
    txid = jbits256(argjson,"txid");
    vout = jint(argjson,"vout");
    for (iambob=0; iambob<=1; iambob++)
    {
        if ( (utxo= LP_utxofind(iambob,txid,vout)) != 0 && utxo->T.spentflag == 0 )
        {
            if ( jobj(argjson,"check") == 0 )
                checktxid = txid, checkvout = vout;
            else
            {
                checktxid = jbits256(argjson,"checktxid");
                checkvout = jint(argjson,"checkvout");
            }
            if ( LP_txvalue(0,utxo->coin,checktxid,checkvout) == 0 )
            {
                if ( LP_mypeer != 0 && LP_mypeer->numutxos > 0 )
                    LP_mypeer->numutxos--;
                utxo->T.spentflag = (uint32_t)time(NULL);
                retval++;
                //printf("indeed txid was spent\n");
            }
        }
    }
    if ( retval > 0 )
        return(clonestr("{\"result\":\"marked as spent\"}"));
    return(clonestr("{\"error\":\"cant find txid to check spent status\"}"));
}

struct LP_utxoinfo *LP_utxoadd(int32_t iambob,int32_t mypubsock,char *symbol,bits256 txid,int32_t vout,int64_t value,bits256 txid2,int32_t vout2,int64_t value2,char *spendscript,char *coinaddr,bits256 pubkey,double profitmargin,char *gui)
{
    uint64_t val,val2=0,tmpsatoshis,bigtxfee = 100000; int32_t spendvini,selector; bits256 spendtxid; char *msg; struct iguana_info *coin; struct _LP_utxoinfo u; struct LP_utxoinfo *utxo = 0;
    if ( symbol == 0 || symbol[0] == 0 || spendscript == 0 || spendscript[0] == 0 || coinaddr == 0 || coinaddr[0] == 0 || bits256_nonz(txid) == 0 || bits256_nonz(txid2) == 0 || vout < 0 || vout2 < 0 || value <= 0 || value2 <= 0 )
    {
        printf("malformed addutxo %d %d %d %d %d %d %d %d %d\n", symbol == 0,spendscript == 0,coinaddr == 0,bits256_nonz(txid) == 0,bits256_nonz(txid2) == 0,vout < 0,vout2 < 0,value <= 0,value2 <= 0);
        return(0);
    }
    if ( (coin= LP_coinfind(symbol)) == 0 || coin->inactive != 0 )
        return(0);
    if ( iambob != 0 && value2 < 9 * (value >> 3) + bigtxfee ) // big txfee padding
    {
        if ( value2 > bigtxfee+20000 )
            tmpsatoshis = (((value2 - bigtxfee) / 9) << 3);
        else return(0);
    } else tmpsatoshis = value;
    char str[65],str2[65],dispflag = (iambob == 0);
    if ( iambob == 0 && bits256_cmp(pubkey,LP_mypubkey) != 0 )
    {
        printf("trying to add Alice utxo when not mine? %s/v%d\n",bits256_str(str,txid),vout);
        return(0);
    }
    if ( LP_iseligible(&val,&val2,iambob,symbol,txid,vout,tmpsatoshis,txid2,vout2) <= 0 )
    {
        printf("iambob.%d utxoadd %s inactive.%u got ineligible txid value %.8f, value2 %.8f, tmpsatoshis %.8f\n",iambob,symbol,coin->inactive,dstr(value),dstr(value2),dstr(tmpsatoshis));
        return(0);
    }
    if ( dispflag != 0 )
        printf("%.8f %.8f %s iambob.%d %s utxoadd.(%.8f %.8f) %s %s\n",dstr(val),dstr(val2),coinaddr,iambob,symbol,dstr(value),dstr(value2),bits256_str(str,txid),bits256_str(str2,txid2));
    dispflag = 1;
    if ( (selector= LP_mempool_vinscan(&spendtxid,&spendvini,symbol,txid,vout,txid2,vout2)) >= 0 )
    {
        printf("utxoadd selector.%d in mempool %s vini.%d",selector,bits256_str(str,spendtxid),spendvini);
        return(0);
    }
    if ( (utxo= LP_utxofinds(iambob,txid,vout,txid2,vout2)) != 0 )
    {
        if ( 0 && LP_ismine(utxo) == 0 )
        {
            char str2[65],str3[65]; printf("iambob.%d %s %s utxoadd.(%.8f %.8f) %s %s\n",iambob,bits256_str(str3,pubkey),symbol,dstr(value),dstr(value2),bits256_str(str,txid),bits256_str(str2,txid2));
            printf("duplicate %.8f %.8f %.8f vs utxo.(%.8f %.8f %.8f)\n",dstr(value),dstr(value2),dstr(tmpsatoshis),dstr(utxo->payment.value),dstr(utxo->deposit.value),dstr(utxo->S.satoshis));
        }
        u = (utxo->iambob != 0) ? utxo->deposit : utxo->fee;
        if ( bits256_cmp(txid,utxo->payment.txid) != 0 || bits256_cmp(txid2,u.txid) != 0 || vout != utxo->payment.vout || value != utxo->payment.value || tmpsatoshis != utxo->S.satoshis || vout2 != u.vout || value2 != u.value || strcmp(symbol,utxo->coin) != 0 || strcmp(spendscript,utxo->spendscript) != 0 || strcmp(coinaddr,utxo->coinaddr) != 0 || bits256_cmp(pubkey,utxo->pubkey) != 0 )
        {
            utxo->T.errors++;
            char str[65],str2[65],str3[65],str4[65],str5[65],str6[65];
            if ( utxo->T.spentflag != 0 || LP_txvalue(0,utxo->coin,utxo->payment.txid,utxo->payment.vout) < utxo->payment.value || LP_txvalue(0,utxo->coin,u.txid,u.vout) < u.value )
            {
                if ( utxo->T.spentflag == 0 )
                    utxo->T.spentflag = (uint32_t)time(NULL);
                printf("original utxo pair not valid\n");
                if ( dispflag != 0 )
                    printf("error on subsequent utxo iambob.%d %.8f %.8f add.(%s %s) when.(%s %s) %d %d %d %d %d %d %d %d %d %d %d pubkeys.(%s vs %s)\n",iambob,dstr(val),dstr(val2),bits256_str(str,txid),bits256_str(str2,txid2),bits256_str(str3,utxo->payment.txid),bits256_str(str4,utxo->deposit.txid),bits256_cmp(txid,utxo->payment.txid) != 0,bits256_cmp(txid2,u.txid) != 0,vout != utxo->payment.vout,tmpsatoshis != utxo->S.satoshis,vout2 != u.vout,value2 != u.value,strcmp(symbol,utxo->coin) != 0,strcmp(spendscript,utxo->spendscript) != 0,strcmp(coinaddr,utxo->coinaddr) != 0,bits256_cmp(pubkey,utxo->pubkey) != 0,value != utxo->payment.value,bits256_str(str5,pubkey),bits256_str(str6,utxo->pubkey));
                utxo = 0;
            }
        }
        else if ( profitmargin > SMALLVAL )
            utxo->S.profitmargin = profitmargin;
        if ( utxo != 0 )
            return(utxo);
    }
    utxo = calloc(1,sizeof(*utxo));
    utxo->S.profitmargin = profitmargin;
    utxo->pubkey = pubkey;
    safecopy(utxo->gui,gui,sizeof(utxo->gui));
    safecopy(utxo->coin,symbol,sizeof(utxo->coin));
    safecopy(utxo->coinaddr,coinaddr,sizeof(utxo->coinaddr));
    safecopy(utxo->spendscript,spendscript,sizeof(utxo->spendscript));
    utxo->payment.txid = txid;
    utxo->payment.vout = vout;
    utxo->payment.value = value;
    utxo->S.satoshis = tmpsatoshis;
    if ( (utxo->iambob= iambob) != 0 )
    {
        utxo->deposit.txid = txid2;
        utxo->deposit.vout = vout2;
        utxo->deposit.value = value2;
    }
    else
    {
        utxo->fee.txid = txid2;
        utxo->fee.vout = vout2;
        utxo->fee.value = value2;
    }
    LP_utxosetkey(utxo->key,txid,vout);
    LP_utxosetkey(utxo->key2,txid2,vout2);
    portable_mutex_lock(&LP_utxomutex);
    HASH_ADD_KEYPTR(hh,LP_utxoinfos[iambob],utxo->key,sizeof(utxo->key),utxo);
    if ( _LP_utxo2find(iambob,txid2,vout2) == 0 )
        HASH_ADD_KEYPTR(hh2,LP_utxoinfos2[iambob],utxo->key2,sizeof(utxo->key2),utxo);
    portable_mutex_unlock(&LP_utxomutex);
    if ( iambob != 0 )
    {
        if ( mypubsock >= 0 )
        {
            msg = jprint(LP_utxojson(utxo),1);
            LP_send(mypubsock,msg,(int32_t)strlen(msg)+1,1);
        } else LP_utxo_clientpublish(utxo);
        if ( LP_mypeer != 0 && LP_ismine(utxo) > 0 )
            LP_mypeer->numutxos++;
    }
    return(utxo);
}

struct LP_utxoinfo *LP_utxoaddjson(int32_t iambob,int32_t pubsock,cJSON *argjson)
{
    struct LP_utxoinfo *utxo;
    if ( jobj(argjson,"iambob") == 0 || iambob != jint(argjson,"iambob") )
    {
        printf("LP_utxoaddjson: iambob.%d != arg.%d obj.%p (%s)\n",iambob,jint(argjson,"iambob"),jobj(argjson,"iambob"),jprint(argjson,0));
        return(0);
    }
    portable_mutex_lock(&LP_UTXOmutex);
    utxo = LP_utxoadd(iambob,pubsock,jstr(argjson,"coin"),jbits256(argjson,"txid"),jint(argjson,"vout"),j64bits(argjson,"value"),jbits256(argjson,"txid2"),jint(argjson,"vout2"),j64bits(argjson,"value2"),jstr(argjson,"script"),jstr(argjson,"address"),jbits256(argjson,"pubkey"),jdouble(argjson,"profit"),jstr(argjson,"gui"));
    portable_mutex_unlock(&LP_UTXOmutex);
    return(utxo);
}

int32_t LP_utxosparse(char *destipaddr,uint16_t destport,char *retstr,uint32_t now)
{
    struct LP_peerinfo *destpeer,*peer; uint32_t argipbits; char *argipaddr; uint16_t argport,pushport,subport; cJSON *array,*item; int32_t i,n=0; bits256 txid; struct LP_utxoinfo *utxo;
    //printf("parse.(%s)\n",retstr);
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
                        peer = LP_addpeer(0,-1,argipaddr,argport,pushport,subport,jdouble(item,"profit"),jint(item,"numpeers"),jint(item,"numutxos"));
                }
                if ( jobj(item,"txid") != 0 )
                {
                    txid = jbits256(item,"txid");
                    //printf("parse.(%s)\n",jprint(item,0));
                    if ( (utxo= LP_utxoaddjson(1,-1,item)) != 0 )
                    {
                        //if ( strcmp(utxo->coin,"HUSH") == 0 )
                        //    printf("%s set lasttime (%s)\n",destipaddr,jprint(item,0));
                        utxo->T.lasttime = now;
                    }
                }
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

int32_t LP_utxosquery(struct LP_peerinfo *mypeer,int32_t mypubsock,char *destipaddr,uint16_t destport,char *coin,int32_t lastn,char *myipaddr,uint16_t myport,double myprofit)
{
    char *retstr; struct LP_peerinfo *peer; uint32_t now; int32_t retval = -1;
    peer = LP_peerfind((uint32_t)calc_ipbits(destipaddr),destport);
    if ( coin == 0 )
        coin = "";
    //printf("utxo query.(%s)\n",destipaddr);
    if ( IAMLP != 0 )
        retstr = issue_LP_getutxos(destipaddr,destport,coin,lastn,myipaddr,myport,myprofit,mypeer != 0 ? mypeer->numpeers : 0,mypeer != 0 ? mypeer->numutxos : 0);
    else retstr = issue_LP_clientgetutxos(destipaddr,destport,coin,100);
    if ( retstr != 0 )
    {
        now = (uint32_t)time(NULL);
        retval = LP_utxosparse(destipaddr,destport,retstr,now);
        //printf("got.(%s)\n",retstr);
        free(retstr);
        /*i = 0;
        if ( lastn >= mypeer->numutxos )
            firsti = -1;
        else firsti = (mypeer->numutxos - lastn);
        HASH_ITER(hh,LP_utxoinfos,utxo,tmp)
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
    }
    return(retval);
}

cJSON *LP_inventory(char *symbol,int32_t iambob)
{
    struct LP_utxoinfo *utxo,*tmp; struct _LP_utxoinfo u; char *myipaddr; cJSON *array; uint64_t val,val2;
    array = cJSON_CreateArray();
    if ( LP_mypeer != 0 )
        myipaddr = LP_mypeer->ipaddr;
    else myipaddr = "127.0.0.1";
    HASH_ITER(hh,LP_utxoinfos[iambob],utxo,tmp)
    {
        //char str[65]; printf("iambob.%d iterate %s\n",iambob,bits256_str(str,LP_mypubkey));
        if ( LP_isunspent(utxo) != 0 && strcmp(symbol,utxo->coin) == 0 && utxo->iambob == iambob && LP_ismine(utxo) > 0 )
        {
            u = (iambob != 0) ? utxo->deposit : utxo->fee;
            if ( LP_iseligible(&val,&val2,iambob,utxo->coin,utxo->payment.txid,utxo->payment.vout,utxo->S.satoshis,u.txid,u.vout) == 0 )
            {
                if ( utxo->T.spentflag == 0 )
                    utxo->T.spentflag = (uint32_t)time(NULL);
            }
            jaddi(array,LP_inventoryjson(cJSON_CreateObject(),utxo));
        }
        //else printf("skip %s %d %d %d %d\n",bits256_str(str,utxo->pubkey),LP_isunspent(utxo) != 0,strcmp(symbol,utxo->coin) == 0,utxo->iambob == iambob,LP_ismine(utxo) > 0);
    }
    return(array);
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

int32_t LP_nearestvalue(int32_t iambob,uint64_t *values,int32_t n,uint64_t targetval)
{
    int32_t i,mini = -1; int64_t dist; uint64_t mindist = (1 << 31);
    for (i=0; i<n; i++)
    {
        dist = (values[i] - targetval);
        if ( iambob != 0 && dist < 0 && -dist < values[i]/10 )
            dist = -dist;
        if ( dist >= 0 && dist < mindist )
        {
            mini = i;
            mindist = dist;
        }
    }
    return(mini);
}

uint64_t LP_privkey_init(int32_t mypubsock,struct iguana_info *coin,bits256 myprivkey,bits256 mypub,uint8_t *pubkey33)
{
    char *script; struct LP_utxoinfo *utxo; cJSON *array,*item; bits256 txid,deposittxid; int32_t used,i,n,iambob,vout,depositvout; uint64_t *values=0,satoshis,depositval,targetval,value,total = 0;
    if ( coin == 0 )
    {
        printf("coin not active\n");
        return(0);
    }
    //printf("privkey init.(%s) %s\n",coin->symbol,coin->smartaddr);
    if ( coin->inactive == 0 && (array= LP_listunspent(coin->symbol,coin->smartaddr)) != 0 )
    {
        if ( is_cJSON_Array(array) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
        {
            for (iambob=0; iambob<=1; iambob++)
            {
                if ( iambob == 0 )
                    values = calloc(n,sizeof(*values));
                else memset(values,0,n * sizeof(*values));
                //if ( iambob == 0 && IAMLP != 0 )
                //    continue;
                used = 0;
                for (i=0; i<n; i++)
                {
                    item = jitem(array,i);
                    satoshis = SATOSHIDEN * jdouble(item,"amount");
                    if ( LP_inventory_prevent(iambob,jbits256(item,"txid"),juint(item,"vout")) == 0 )
                        values[i] = satoshis;
                    else used++;
                    //printf("%.8f ",dstr(satoshis));
                }
                //printf("array.%d\n",n);
                while ( used < n-1 )
                {
                    //printf("used.%d of n.%d\n",used,n);
                    if ( (i= LP_maxvalue(values,n)) >= 0 )
                    {
                        item = jitem(array,i);
                        deposittxid = jbits256(item,"txid");
                        depositvout = juint(item,"vout");
                        script = jstr(item,"scriptPubKey");
                        depositval = values[i];
                        values[i] = 0, used++;
                        if ( iambob == 0 )
                            targetval = (depositval / 776) + 100000;
                        else targetval = (depositval / 9) * 8 + 100000;
                        //printf("i.%d %.8f target %.8f\n",i,dstr(depositval),dstr(targetval));
                        if ( (i= LP_nearestvalue(iambob,values,n,targetval)) < 0 && iambob != 0 )
                            targetval /= 4;
                        if ( (i= LP_nearestvalue(iambob,values,n,targetval)) >= 0 )
                        {
                            item = jitem(array,i);
                            txid = jbits256(item,"txid");
                            vout = juint(item,"vout");
                            if ( jstr(item,"scriptPubKey") != 0 && strcmp(script,jstr(item,"scriptPubKey")) == 0 )
                            {
                                value = values[i];
                                values[i] = 0, used++;
                                portable_mutex_lock(&LP_UTXOmutex);
                                if ( iambob != 0 )
                                {
                                    if ( (utxo= LP_utxoadd(1,mypubsock,coin->symbol,txid,vout,value,deposittxid,depositvout,depositval,script,coin->smartaddr,mypub,LP_mypeer != 0 ? LP_mypeer->profitmargin : 0.01,LP_gui)) != 0 )
                                    {
                                    }
                                }
                                else
                                {
                                    if ( (utxo= LP_utxoadd(0,mypubsock,coin->symbol,deposittxid,depositvout,depositval,txid,vout,value,script,coin->smartaddr,mypub,0.,LP_gui)) != 0 )
                                    {
                                    }
                                }
                                portable_mutex_unlock(&LP_UTXOmutex);
                                total += value;
                            }
                        }
                    } else break;
                }
                if ( iambob == 1 )
                    free(values);
            }
        }
        free_json(array);
    }
    //printf("privkey.%s %.8f\n",symbol,dstr(total));
    return(total);
}

bits256 LP_privkeycalc(void *ctx,uint8_t *pubkey33,bits256 *pubkeyp,struct iguana_info *coin,char *passphrase,char *wifstr)
{
    static uint32_t counter;
    bits256 privkey,userpub,userpass,checkkey; char tmpstr[128]; cJSON *retjson; uint8_t tmptype,rmd160[20];
    if ( passphrase != 0 && passphrase[0] != 0 )
        conv_NXTpassword(privkey.bytes,pubkeyp->bytes,(uint8_t *)passphrase,(int32_t)strlen(passphrase));
    else
    {
        bitcoin_wif2priv(&tmptype,&privkey,wifstr);
        if ( 0 )
        {
            char str[65],str2[65];
            checkkey = iguana_wif2privkey(wifstr);
            if ( bits256_cmp(checkkey,privkey) != 0 )
                printf("WIF.(%s) -> %s or %s?\n",wifstr,bits256_str(str,privkey),bits256_str(str2,checkkey));
        }
    }
    bitcoin_priv2pub(ctx,pubkey33,coin->smartaddr,privkey,coin->taddr,coin->pubtype);
    if ( coin->counter == 0 )
    {
        coin->counter++;
        bitcoin_priv2wif(tmpstr,privkey,coin->wiftype);
        bitcoin_addr2rmd160(coin->taddr,&tmptype,rmd160,coin->smartaddr);
        LP_privkeyadd(privkey,rmd160);
        if ( 0 && (coin->pubtype != 60 || strcmp(coin->symbol,"KMD") == 0) )
            printf("%s (%s) %d wif.(%s) (%s)\n",coin->symbol,coin->smartaddr,coin->pubtype,tmpstr,passphrase);
        if ( counter++ == 0 )
        {
            bitcoin_priv2wif(USERPASS_WIFSTR,privkey,188);
            conv_NXTpassword(userpass.bytes,pubkeyp->bytes,(uint8_t *)USERPASS_WIFSTR,(int32_t)strlen(USERPASS_WIFSTR));
            userpub = curve25519(userpass,curve25519_basepoint9());
            printf("userpass.(%s)\n",bits256_str(USERPASS,userpub));
        }
        if ( (retjson= LP_importprivkey(coin->symbol,tmpstr,coin->smartaddr,-1)) != 0 )
        {
            if ( jobj(retjson,"error") != 0 )
            {
                printf("cant importprivkey.%s -> (%s), abort session\n",coin->symbol,jprint(retjson,1));
                exit(-1);
            }
        }
    }
    LP_mypubkey = *pubkeyp = curve25519(privkey,curve25519_basepoint9());
    //printf("privkey.(%s) -> LP_mypubkey.(%s)\n",bits256_str(str,privkey),bits256_str(str2,LP_mypubkey));
    return(privkey);
}

void LP_privkey_updates(void *ctx,int32_t pubsock,char *passphrase,int32_t initonly)
{
    struct iguana_info *coin,*tmp; bits256 pubkey,privkey; uint8_t pubkey33[33];
    memset(privkey.bytes,0,sizeof(privkey));
    pubkey = privkey;
    HASH_ITER(hh,LP_coins,coin,tmp)
    {
        //printf("i.%d of %d\n",i,LP_numcoins);
        if ( bits256_nonz(privkey) == 0 || coin->smartaddr[0] == 0 )
            privkey = LP_privkeycalc(ctx,pubkey33,&pubkey,coin,passphrase,"");
        if ( coin->inactive == 0 && initonly == 0 )
            LP_privkey_init(pubsock,coin,privkey,pubkey,pubkey33);
    }
}


