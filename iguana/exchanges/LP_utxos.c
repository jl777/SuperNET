
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
    if ( utxo != 0 && bits256_cmp(utxo->pubkey,G.LP_mypub25519) == 0 )
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
    struct LP_address_utxo *up; struct _LP_utxoinfo u; struct iguana_info *coin;
    if ( (coin= LP_coinfind(utxo->coin)) == 0 )
        return(0);
    if ( (up= LP_address_utxofind(coin,utxo->coinaddr,utxo->payment.txid,utxo->payment.vout)) != 0 && up->spendheight > 0 )
    {
        utxo->T.spentflag = up->spendheight;
        return(0);
    }
    u = (utxo->iambob != 0) ? utxo->deposit : utxo->fee;
    if ( (up= LP_address_utxofind(coin,utxo->coinaddr,u.txid,u.vout)) != 0 && up->spendheight > 0 )
    {
        utxo->T.spentflag = up->spendheight;
        return(0);
    }
    if ( utxo != 0 && utxo->T.spentflag == 0 && LP_isavailable(utxo) > 0 )
        return(1);
    else return(0);
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

cJSON *LP_inventoryjson(cJSON *item,struct LP_utxoinfo *utxo)
{
    struct _LP_utxoinfo u;
    //jaddstr(item,"method","oldutxo");
    if ( utxo == 0 )
        return(item);
    if ( utxo->gui[0] != 0 )
        jaddstr(item,"gui",utxo->gui);
    jaddstr(item,"coin",utxo->coin);
    //jaddnum(item,"now",time(NULL));
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
        jaddbits256(item,"srchash",utxo->pubkey);//LP_mypub25519);
        if ( bits256_nonz(utxo->S.otherpubkey) != 0 )
            jaddbits256(item,"desthash",utxo->S.otherpubkey);
    }
    else
    {
        jaddbits256(item,"desthash",utxo->pubkey);//LP_mypub25519);
        if ( bits256_nonz(utxo->S.otherpubkey) != 0 )
            jaddbits256(item,"srchash",utxo->S.otherpubkey);
    }
    if ( utxo->S.swap != 0 )
        jaddstr(item,"swap","in progress");
    if ( utxo->T.spentflag != 0 )
        jaddnum(item,"spent",utxo->T.spentflag);
    jaddnum(item,"session",utxo->T.sessionid);
    return(item);
}

cJSON *LP_utxojson(struct LP_utxoinfo *utxo)
{
    cJSON *item = cJSON_CreateObject();
    item = LP_inventoryjson(item,utxo);
    jaddbits256(item,"pubkey",utxo->pubkey);
    //jaddnum(item,"profit",utxo->S.profitmargin);
    jaddstr(item,"base",utxo->coin);
    //jaddstr(item,"script",utxo->spendscript);
    return(item);
}

struct LP_utxoinfo *LP_utxo_bestfit(char *symbol,uint64_t destsatoshis)
{
    uint64_t srcvalue,srcvalue2; struct LP_utxoinfo *utxo,*tmp,*bestutxo = 0; int32_t bestsize,iambob = 0;
    if ( symbol == 0 || destsatoshis == 0 )
    {
        printf("LP_utxo_bestfit error symbol.%p %.8f\n",symbol,dstr(destsatoshis));
        return(0);
    }
    // jl777 remove mempool
    HASH_ITER(hh,G.LP_utxoinfos[iambob],utxo,tmp)
    {
        //char str[65]; printf("s%u %d [%.8f vs %.8f] check %s.%s avail.%d ismine.%d >= %d\n",utxo->T.spentflag,LP_iseligible(&srcvalue,&srcvalue2,utxo->iambob,symbol,utxo->payment.txid,utxo->payment.vout,utxo->S.satoshis,utxo->fee.txid,utxo->fee.vout),dstr(destsatoshis),dstr(utxo->S.satoshis),utxo->coin,bits256_str(str,utxo->payment.txid),LP_isavailable(utxo) > 0,LP_ismine(utxo) > 0,utxo->S.satoshis >= destsatoshis);
        if ( strcmp(symbol,utxo->coin) != 0 )
            continue;
        if ( LP_isavailable(utxo) > 0 && LP_ismine(utxo) > 0 )
        {
            bestsize = 0;
            if ( bestutxo == 0 )
            {
                if ( utxo->S.satoshis > destsatoshis/LP_MINCLIENTVOL )
                    bestsize = 1;
            }
            else
            {
                if ( bestutxo->S.satoshis < destsatoshis )
                {
                    if ( utxo->S.satoshis > destsatoshis )
                        bestsize = 1;
                    else if ( utxo->S.satoshis > bestutxo->S.satoshis )
                        bestsize = 1;
                }
                else
                {
                    if ( utxo->S.satoshis > destsatoshis && utxo->S.satoshis < bestutxo->S.satoshis )
                        bestsize = 1;
                }
            }
            if ( bestsize > 0 )
            {
                if ( LP_iseligible(&srcvalue,&srcvalue2,utxo->iambob,symbol,utxo->payment.txid,utxo->payment.vout,utxo->S.satoshis,utxo->fee.txid,utxo->fee.vout) == 0 )
                {
                    printf("not elibible\n");
                    //if ( utxo->T.spentflag == 0 )
                    //    utxo->T.spentflag = (uint32_t)time(NULL);
                    continue;
                }
                bestutxo = utxo;
            } // else printf("skip alice utxo %.8f vs dest %.8f\n",dstr(utxo->S.satoshis),dstr(destsatoshis));
        }
    }
    return(bestutxo);
}

void LP_spentnotify(struct LP_utxoinfo *utxo,int32_t selector)
{
    if ( utxo == 0 )
        return;
    utxo->T.spentflag = (uint32_t)time(NULL);
}

struct LP_utxoinfo *LP_utxoadd(int32_t iambob,char *symbol,bits256 txid,int32_t vout,int64_t value,bits256 txid2,int32_t vout2,int64_t value2,char *coinaddr,bits256 pubkey,char *gui,uint32_t sessionid)
{
    uint64_t val,val2=0,tmpsatoshis,txfee; int32_t spendvini,numconfirms,selector; bits256 spendtxid; struct iguana_info *coin; struct _LP_utxoinfo u; struct LP_utxoinfo *utxo = 0;
    if ( symbol == 0 || symbol[0] == 0 || coinaddr == 0 || coinaddr[0] == 0 || bits256_nonz(txid) == 0 || bits256_nonz(txid2) == 0 || vout < 0 || vout2 < 0 || value <= 0 || value2 <= 0 )//|| sessionid == 0 )
    {
        char str[65],str2[65]; printf("REJECT %s iambob.%d %s utxoadd.(%.8f %.8f) %s/v%d %s/v%d\n",coinaddr,iambob,symbol,dstr(value),dstr(value2),bits256_str(str,txid),vout,bits256_str(str2,txid2),vout2);
        printf("session.%u addutxo %d %d %d %d %d %d %d %d\n",sessionid,symbol == 0,coinaddr == 0,bits256_nonz(txid) == 0,bits256_nonz(txid2) == 0,vout < 0,vout2 < 0,value <= 0,value2 <= 0);
        return(0);
    }
    if ( (coin= LP_coinfind(symbol)) == 0 || (IAMLP == 0 && coin->inactive != 0) )
    {
        //printf("LP_utxoadd reject inactive %s\n",symbol);
        return(0);
    }
    txfee = LP_txfeecalc(coin,0,0);
    if ( iambob != 0 && value2 < 9 * (value >> 3) + 2*txfee ) // big txfee padding
    {
        if ( value2 > 2*txfee )
            tmpsatoshis = (((value2 - 2*txfee) / 9) << 3);
        else
        {
            printf("value2 %.8f <= 2 * %.8f\n",dstr(value2),dstr(txfee));
            return(0);
        }
    } else tmpsatoshis = (value - txfee);
    char str[65],str2[65],dispflag = 0;//(iambob == 0);
    if ( iambob == 0 && bits256_cmp(pubkey,G.LP_mypub25519) != 0 )
    {
        printf("trying to add Alice utxo when not mine? %s/v%d\n",bits256_str(str,txid),vout);
        return(0);
    }
    if ( coin->inactive == 0 )
    {
        if ( LP_iseligible(&val,&val2,iambob,symbol,txid,vout,tmpsatoshis,txid2,vout2) <= 0 )
        {
            static uint32_t counter;
            if ( counter++ < 3 )
                printf("iambob.%d utxoadd %s inactive.%u got ineligible txid value %.8f:%.8f, value2 %.8f:%.8f, tmpsatoshis %.8f\n",iambob,symbol,coin->inactive,dstr(value),dstr(val),dstr(value2),dstr(val2),dstr(tmpsatoshis));
            return(0);
        }
        if ( (numconfirms= LP_numconfirms(symbol,coinaddr,txid,vout,0)) <= 0 )
        {
            printf("LP_utxoadd reject numconfirms.%d %s.%s\n",numconfirms,symbol,bits256_str(str,txid));
            return(0);
        }
        if ( (numconfirms= LP_numconfirms(symbol,coinaddr,txid2,vout2,0)) <= 0 )
        {
            printf("LP_utxoadd reject2 numconfirms.%d %s %s/v%d\n",numconfirms,symbol,bits256_str(str,txid2),vout2);
            return(0);
        }
    }
    else
    {
        val = value;
        val2 = value2;
    }
    dispflag = 0;
    if ( dispflag != 0 )
        printf("%.8f %.8f %s iambob.%d %s utxoadd.(%.8f %.8f) %s %s\n",dstr(val),dstr(val2),coinaddr,iambob,symbol,dstr(value),dstr(value2),bits256_str(str,txid),bits256_str(str2,txid2));
    dispflag = 1;
    if ( (utxo= LP_utxofinds(iambob,txid,vout,txid2,vout2)) != 0 )
    {
        if ( 0 && LP_ismine(utxo) == 0 )
        {
            char str2[65],str3[65]; printf("iambob.%d %s %s utxoadd.(%.8f %.8f) %s %s\n",iambob,bits256_str(str3,pubkey),symbol,dstr(value),dstr(value2),bits256_str(str,txid),bits256_str(str2,txid2));
            printf("duplicate %.8f %.8f %.8f vs utxo.(%.8f %.8f %.8f)\n",dstr(value),dstr(value2),dstr(tmpsatoshis),dstr(utxo->payment.value),dstr(utxo->deposit.value),dstr(utxo->S.satoshis));
        }
        u = (utxo->iambob != 0) ? utxo->deposit : utxo->fee;
        if ( bits256_cmp(txid,utxo->payment.txid) != 0 || bits256_cmp(txid2,u.txid) != 0 || vout != utxo->payment.vout || value != utxo->payment.value || tmpsatoshis != utxo->S.satoshis || vout2 != u.vout || value2 != u.value || strcmp(symbol,utxo->coin) != 0 || strcmp(coinaddr,utxo->coinaddr) != 0 || bits256_cmp(pubkey,utxo->pubkey) != 0 )
        {
            utxo->T.errors++;
            char str[65],str2[65],str3[65],str4[65],str5[65],str6[65];
            if ( utxo->T.spentflag != 0 || LP_txvalue(0,utxo->coin,utxo->payment.txid,utxo->payment.vout) < utxo->payment.value || LP_txvalue(0,utxo->coin,u.txid,u.vout) < u.value )
            {
                //if ( utxo->T.spentflag == 0 )
                //    utxo->T.spentflag = (uint32_t)time(NULL);
                printf("original utxo pair not valid\n");
                if ( dispflag != 0 )
                    printf("error on subsequent utxo iambob.%d %.8f %.8f add.(%s %s) when.(%s %s) %d %d %d %d %d %d %d %d %d %d pubkeys.(%s vs %s)\n",iambob,dstr(val),dstr(val2),bits256_str(str,txid),bits256_str(str2,txid2),bits256_str(str3,utxo->payment.txid),bits256_str(str4,utxo->deposit.txid),bits256_cmp(txid,utxo->payment.txid) != 0,bits256_cmp(txid2,u.txid) != 0,vout != utxo->payment.vout,tmpsatoshis != utxo->S.satoshis,vout2 != u.vout,value2 != u.value,strcmp(symbol,utxo->coin) != 0,strcmp(coinaddr,utxo->coinaddr) != 0,bits256_cmp(pubkey,utxo->pubkey) != 0,value != utxo->payment.value,bits256_str(str5,pubkey),bits256_str(str6,utxo->pubkey));
                utxo = 0;
            }
        }
        if ( utxo != 0 )
        {
            if ( utxo->T.sessionid == 0 )
                utxo->T.sessionid = sessionid;
            //else if ( profitmargin > SMALLVAL )
            //    utxo->S.profitmargin = profitmargin;
            utxo->T.lasttime = (uint32_t)time(NULL);
            //printf("return existing utxo[%d] %s %s\n",iambob,bits256_str(str,utxo->payment.txid),bits256_str(str2,iambob != 0 ? utxo->deposit.txid : utxo->fee.txid));
            return(utxo);
        }
    }
    utxo = calloc(1,sizeof(*utxo));
    //utxo->S.profitmargin = profitmargin;
    utxo->pubkey = pubkey;
    safecopy(utxo->gui,gui,sizeof(utxo->gui));
    safecopy(utxo->coin,symbol,sizeof(utxo->coin));
    safecopy(utxo->coinaddr,coinaddr,sizeof(utxo->coinaddr));
    //safecopy(utxo->spendscript,spendscript,sizeof(utxo->spendscript));
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
    if ( LP_ismine(utxo) > 0 )
        utxo->T.sessionid = G.LP_sessionid;
    else utxo->T.sessionid = sessionid;
    if ( coin->inactive == 0 && (selector= LP_mempool_vinscan(&spendtxid,&spendvini,symbol,coinaddr,txid,vout,txid2,vout2)) >= 0 )
    {
        printf("utxoadd selector.%d spent in mempool %s vini.%d",selector,bits256_str(str,spendtxid),spendvini);
        utxo->T.spentflag = (uint32_t)time(NULL);
    }
    //printf(" %s %.8f %.8f %p addutxo.%d (%s %s) session.%u iambob.%d <<<<<<<<<<<<<<<\n",symbol,dstr(value),dstr(value2),utxo,LP_ismine(utxo) > 0,bits256_str(str,utxo->payment.txid),bits256_str(str2,iambob != 0 ? utxo->deposit.txid : utxo->fee.txid),utxo->T.sessionid,iambob);
    portable_mutex_lock(&LP_utxomutex);
    HASH_ADD_KEYPTR(hh,G.LP_utxoinfos[iambob],utxo->key,sizeof(utxo->key),utxo);
    if ( _LP_utxo2find(iambob,txid2,vout2) == 0 )
        HASH_ADD_KEYPTR(hh2,G.LP_utxoinfos2[iambob],utxo->key2,sizeof(utxo->key2),utxo);
    portable_mutex_unlock(&LP_utxomutex);
    if ( iambob != 0 )
    {
        if ( LP_ismine(utxo) > 0 )
        {
            //LP_utxo_clientpublish(utxo);
            if ( LP_mypeer != 0 )
                utxo->T.lasttime = (uint32_t)time(NULL);
        }
    }
    return(utxo);
}

cJSON *LP_inventory(char *symbol)
{
    struct LP_utxoinfo *utxo,*tmp; struct _LP_utxoinfo u; char *myipaddr; cJSON *array; uint64_t val,val2; int32_t iambob = 0; struct iguana_info *coin;
    array = cJSON_CreateArray();
    if ( LP_mypeer != 0 )
        myipaddr = LP_mypeer->ipaddr;
    else myipaddr = "127.0.0.1";
    if ( (coin= LP_coinfind(symbol)) != 0 )
        LP_listunspent_both(symbol,coin->smartaddr,0);
    HASH_ITER(hh,G.LP_utxoinfos[iambob],utxo,tmp)
    {
        char str[65];
        //printf("iambob.%d iterate %s\n",iambob,bits256_str(str,LP_mypub25519));
        if ( LP_isunspent(utxo) != 0 && strcmp(symbol,utxo->coin) == 0 && utxo->iambob == iambob && LP_ismine(utxo) > 0 )
        {
            u = (iambob != 0) ? utxo->deposit : utxo->fee;
            if ( LP_iseligible(&val,&val2,iambob,utxo->coin,utxo->payment.txid,utxo->payment.vout,utxo->S.satoshis,u.txid,u.vout) == 0 )
            {
                //if ( utxo->T.spentflag == 0 )
                //    utxo->T.spentflag = (uint32_t)time(NULL);
                printf("%s %s ineligible %.8f %.8f\n",utxo->coin,bits256_str(str,u.txid),dstr(val),dstr(val2));
                continue;
            }
            //if ( iambob != 0 )
            //    LP_utxo_clientpublish(utxo);
            jaddi(array,LP_inventoryjson(cJSON_CreateObject(),utxo));
        }
        else if ( 0 && LP_ismine(utxo) > 0 && strcmp(symbol,utxo->coin) == 0 )
            printf("skip %s %s %d %d %d %d\n",utxo->coin,bits256_str(str,utxo->payment.txid),LP_isunspent(utxo) != 0,strcmp(symbol,utxo->coin) == 0,utxo->iambob == iambob,LP_ismine(utxo) > 0);
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
        //printf("(%.8f %.8f %.8f).%d ",dstr(values[i]),dstr(dist),dstr(mindist),mini);
        if ( dist >= 0 && dist < mindist )
        {
            mini = i;
            mindist = dist;
        }
    }
    return(mini);
}

int32_t LP_privkey_init(int32_t mypubsock,struct iguana_info *coin,bits256 myprivkey,bits256 mypub)
{
    int32_t enable_utxos = 0;
    char *script,destaddr[64]; struct LP_utxoinfo *utxo; cJSON *array,*item; bits256 txid,deposittxid; int32_t used,i,flag=0,height,n,cmpflag,iambob,vout,depositvout; uint64_t *values=0,satoshis,txfee,depositval,value,total = 0; int64_t targetval;
    if ( coin == 0 || (IAMLP == 0 && coin->inactive != 0) )
    {
        //printf("coin not active\n");
        return(0);
    }
    //printf("privkey init.(%s) %s\n",coin->symbol,coin->smartaddr);
    if ( coin->inactive == 0 )
        LP_listunspent_issue(coin->symbol,coin->smartaddr,0);
    LP_address(coin,coin->smartaddr);
    if ( coin->inactive == 0 && (array= LP_listunspent(coin->symbol,coin->smartaddr)) != 0 )
    {
        txfee = LP_txfeecalc(coin,0,0);
        if ( is_cJSON_Array(array) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
        {
            coin->numutxos = n;
            //printf("LP_privkey_init %s %s\n",coin->symbol,jprint(array,0));
            for (iambob=0; iambob<=1; iambob++)
            {
                if ( iambob == 0 )
                    values = calloc(n,sizeof(*values));
                else memset(values,0,n * sizeof(*values));
                used = 0;
                for (i=0; i<n; i++)
                {
                    item = jitem(array,i);
                    if ( coin->electrum == 0 )
                    {
                        txid = jbits256(item,"txid");
                        vout = juint(item,"vout");
                        value = LP_value_extract(item,0);
                        height = LP_txheight(coin,txid);//LP_getheight(coin) - jint(item,"confirmations") + 1;
                    }
                    else
                    {
                        txid = jbits256(item,"tx_hash");
                        vout = juint(item,"tx_pos");
                        value = j64bits(item,"value");
                        height = jint(item,"height");
                    }
                    satoshis = LP_txvalue(destaddr,coin->symbol,txid,vout);
                    if ( satoshis != 0 && satoshis != value )
                        printf("%s %s unexpected privkey_init value mismatch %.8f vs %.8f (%s) %.8f %.8f\n",coin->symbol,coin->smartaddr,dstr(satoshis),dstr(value),jprint(item,0),jdouble(item,"amount"),jdouble(item,"interest"));
                    if ( LP_inventory_prevent(iambob,coin->symbol,txid,vout) == 0 && height > 0 )
                    {
                        //printf("%s\n",jprint(item,0));
                        values[i] = satoshis;
                        //flag += LP_address_utxoadd(coin,destaddr,txid,vout,satoshis,height,-1);
                    } else used++;
                }
                //printf("array.%d\n",n);
                while ( used < n-1 )
                {
                    //for (i=0; i<n; i++)
                    //   printf("%.8f ",dstr(values[i]));
                    //printf("used.%d of n.%d\n",used,n);
                    if ( (i= LP_maxvalue(values,n)) >= 0 )
                    {
                        item = jitem(array,i);
                        if ( coin->electrum == 0 )
                        {
                            deposittxid = jbits256(item,"txid");
                            depositvout = juint(item,"vout");
                            script = jstr(item,"scriptPubKey");
                        }
                        else
                        {
                            deposittxid = jbits256(item,"tx_hash");
                            depositvout = juint(item,"tx_pos");
                            script = coin->smartaddr;
                        }
                        depositval = values[i];
                        values[i] = 0, used++;
                        if ( iambob == 0 )
                            targetval = (depositval / 776) + txfee;
                        else targetval = (depositval / 9) * 8 + 2*txfee;
                        if ( targetval < txfee*2 )
                            targetval = txfee*2;
                        //printf("iambob.%d i.%d deposit %.8f min %.8f target %.8f\n",iambob,i,dstr(depositval),dstr((1+LP_MINSIZE_TXFEEMULT)*txfee),dstr(targetval));
                        if ( depositval < (1+LP_MINSIZE_TXFEEMULT)*txfee )
                            continue;
                        i = -1;
                        if ( iambob != 0 )
                        {
                            if ( (i= LP_nearestvalue(iambob,values,n,targetval)) < 0 )
                                targetval /= 4;
                            if ( targetval < txfee*(1+LP_MINSIZE_TXFEEMULT) )
                                continue;
                        }
                        if ( i >= 0 || (i= LP_nearestvalue(iambob,values,n,targetval)) >= 0 )
                        {
                            //printf("iambob.%d i.%d %.8f target %.8f\n",iambob,i,dstr(depositval),dstr(targetval));
                            item = jitem(array,i);
                            cmpflag = 0;
                            if ( coin->electrum == 0 )
                            {
                                txid = jbits256(item,"txid");
                                vout = juint(item,"vout");
                                if ( jstr(item,"scriptPubKey") != 0 && strcmp(script,jstr(item,"scriptPubKey")) == 0 )
                                    cmpflag = 1;
                            }
                            else
                            {
                                txid = jbits256(item,"tx_hash");
                                vout = juint(item,"tx_pos");
                                cmpflag = 1;
                            }
                            if ( cmpflag != 0 )
                            {
                                value = values[i];
                                values[i] = 0, used++;
                                portable_mutex_lock(&LP_UTXOmutex);
                                if ( iambob != 0 )
                                {
                                    if ( (utxo= LP_utxoadd(1,coin->symbol,txid,vout,value,deposittxid,depositvout,depositval,coin->smartaddr,mypub,LP_gui,G.LP_sessionid)) != 0 )
                                    {
                                    }
                                }
                                else
                                {
                                    //printf("call utxoadd\n");
                                    if ( (utxo= LP_utxoadd(0,coin->symbol,deposittxid,depositvout,depositval,txid,vout,value,coin->smartaddr,mypub,LP_gui,G.LP_sessionid)) != 0 )
                                    {
                                    }
                                }
                                portable_mutex_unlock(&LP_UTXOmutex);
                                total += value;
                            } // else printf("scriptmismatch.(%s) vs %s\n",script,jprint(item,0));
                        } //else printf("nothing near i.%d\n",i);
                    } else break;
                }
                if ( enable_utxos == 0 )
                    break;
            }
        }
        free_json(array);
        if ( flag != 0 )
            LP_postutxos(coin->symbol,coin->smartaddr);
    }
    if ( values != 0 )
        free(values);
    //printf("privkey.%s %.8f\n",symbol,dstr(total));
    return(flag);
}

char *LP_secretaddresses(void *ctx,char *prefix,char *passphrase,int32_t n,uint8_t taddr,uint8_t pubtype)
{
    int32_t i; uint8_t tmptype,pubkey33[33],rmd160[20]; char output[777*45],str[65],str2[65],buf[8192],wifstr[128],coinaddr[64]; bits256 checkprivkey,privkey,pubkey; cJSON *retjson;
    retjson = cJSON_CreateObject();
    if ( prefix == 0 || prefix[0] == 0 )
        prefix = "secretaddress";
    if ( passphrase == 0 || passphrase[0] == 0 )
        passphrase = "password";
    if ( n <= 0 )
        n = 16;
    else if ( n > 777 )
        n = 777;
    conv_NXTpassword(privkey.bytes,pubkey.bytes,(uint8_t *)passphrase,(int32_t)strlen(passphrase));
    bitcoin_priv2pub(ctx,pubkey33,coinaddr,privkey,taddr,pubtype);
    printf("generator (%s) secrets.[%d] <%s> t.%u p.%u\n",coinaddr,n,passphrase,taddr,pubtype);
    sprintf(output,"\"addresses\":[");
    for (i=0; i<n; i++)
    {
        sprintf(buf,"%s %s %03d",prefix,passphrase,i);
        conv_NXTpassword(privkey.bytes,pubkey.bytes,(uint8_t *)buf,(int32_t)strlen(buf));
        bitcoin_priv2pub(ctx,pubkey33,coinaddr,privkey,taddr,pubtype);
        bitcoin_priv2wif(0,wifstr,privkey,188);
        bitcoin_wif2priv(0,&tmptype,&checkprivkey,wifstr);
        bitcoin_addr2rmd160(taddr,&tmptype,rmd160,coinaddr);
        if ( bits256_cmp(checkprivkey,privkey) != 0 )
        {
            printf("WIF.(%s) error -> %s vs %s?\n",wifstr,bits256_str(str,privkey),bits256_str(str2,checkprivkey));
            free_json(retjson);
            return(clonestr("{\"error\":\"couldnt validate wifstr\"}"));
        }
        else if ( tmptype != pubtype )
        {
            printf("checktype.%d != pubtype.%d\n",tmptype,pubtype);
            free_json(retjson);
            return(clonestr("{\"error\":\"couldnt validate pubtype\"}"));
        }
        jaddstr(retjson,coinaddr,wifstr);
        sprintf(output+strlen(output),"\\\"%s\\\"%c ",coinaddr,i<n-1?',':' ');
        printf("./komodo-cli jumblr_secret %s\n",coinaddr);
    }
    printf("%s]\n",output);
    return(jprint(retjson,1));
}

bits256 LP_privkeycalc(void *ctx,uint8_t *pubkey33,bits256 *pubkeyp,struct iguana_info *coin,char *passphrase,char *wifstr)
{
    //static uint32_t counter;
    bits256 privkey,userpub,userpass,checkkey; char tmpstr[128]; cJSON *retjson; uint8_t tmptype;
    if ( passphrase != 0 && passphrase[0] != 0 )
    {
        conv_NXTpassword(privkey.bytes,pubkeyp->bytes,(uint8_t *)passphrase,(int32_t)strlen(passphrase));
        //vcalc_sha256(0,checkkey.bytes,(uint8_t *)passphrase,(int32_t)strlen(passphrase));
        //printf("SHA256.(%s) ",bits256_str(pstr,checkkey));
        //printf("privkey.(%s)\n",bits256_str(pstr,privkey));
    }
    else
    {
        bitcoin_wif2priv(coin->wiftaddr,&tmptype,&privkey,wifstr);
        if ( 0 )
        {
            char str[65],str2[65];
            checkkey = iguana_wif2privkey(wifstr);
            if ( bits256_cmp(checkkey,privkey) != 0 )
                printf("WIF.(%s) -> %s or %s?\n",wifstr,bits256_str(str,privkey),bits256_str(str2,checkkey));
        }
    }
    privkey.bytes[0] &= 248, privkey.bytes[31] &= 127, privkey.bytes[31] |= 64;
    bitcoin_priv2pub(ctx,coin->pubkey33,coin->smartaddr,privkey,coin->taddr,coin->pubtype);
    if ( coin->counter == 0 )
    {
        coin->counter++;
        memcpy(G.LP_pubsecp,coin->pubkey33,33);
        bitcoin_priv2wif(coin->wiftaddr,tmpstr,privkey,coin->wiftype);
        bitcoin_addr2rmd160(coin->taddr,&tmptype,G.LP_myrmd160,coin->smartaddr);
        LP_privkeyadd(privkey,G.LP_myrmd160);
        G.LP_privkey = privkey;
        if ( 0 && (coin->pubtype != 60 || strcmp(coin->symbol,"KMD") == 0) )
            printf("%s (%s) %d wif.(%s) (%s)\n",coin->symbol,coin->smartaddr,coin->pubtype,tmpstr,passphrase);
        if ( G.counter++ == 0 )
        {
            bitcoin_priv2wif(coin->wiftaddr,G.USERPASS_WIFSTR,privkey,188);
            bitcoin_wif2priv(coin->wiftaddr,&tmptype,&checkkey,G.USERPASS_WIFSTR);
            if ( bits256_cmp(checkkey,privkey) != 0 )
            {
                char str[65],str2[65];
                printf("FATAL ERROR converting USERPASS_WIFSTR %s -> %s != %s\n",G.USERPASS_WIFSTR,bits256_str(str,checkkey),bits256_str(str2,privkey));
                exit(-1);
            }
            conv_NXTpassword(userpass.bytes,pubkeyp->bytes,(uint8_t *)G.USERPASS_WIFSTR,(int32_t)strlen(G.USERPASS_WIFSTR));
            userpub = curve25519(userpass,curve25519_basepoint9());
            printf("userpass.(%s)\n",bits256_str(G.USERPASS,userpub));
        }
    }
    if ( coin->importedprivkey == 0 && coin->electrum == 0 && coin->userpass[0] != 0 && LP_getheight(coin) > 0 )
    {
        LP_listunspent_issue(coin->symbol,coin->smartaddr,0);
        if ( (retjson= LP_importprivkey(coin->symbol,tmpstr,coin->smartaddr,-1)) != 0 )
        {
            if ( jobj(retjson,"error") != 0 )
            {
                printf("cant importprivkey.%s -> (%s), abort session\n",coin->symbol,jprint(retjson,1));
                exit(-1);
            }
        } else free_json(retjson);
        coin->importedprivkey = (uint32_t)time(NULL);
    }
    vcalc_sha256(0,checkkey.bytes,privkey.bytes,sizeof(privkey));
    checkkey.bytes[0] &= 248, checkkey.bytes[31] &= 127, checkkey.bytes[31] |= 64;
    G.LP_mypub25519 = *pubkeyp = curve25519(checkkey,curve25519_basepoint9());
    G.LP_mypriv25519 = checkkey;
    LP_pubkeyadd(G.LP_mypub25519);
    return(privkey);
}

void LP_privkey_updates(void *ctx,int32_t pubsock,char *passphrase)
{
    struct iguana_info *coin,*tmp; bits256 pubkey,privkey; uint8_t pubkey33[33]; int32_t initonly;
    initonly = (passphrase != 0);
    memset(privkey.bytes,0,sizeof(privkey));
    memset(pubkey.bytes,0,sizeof(pubkey));
	//printf("Total coins: %d\n", HASH_COUNT(LP_coins));
	//int num_iter = 0;
    HASH_ITER(hh,LP_coins,coin,tmp)
    {
		//printf("LP_privkey_updates [%02d / %02d]\n", num_iter++, HASH_COUNT(LP_coins));
        if ( initonly != 0 )
        {
            coin->counter = 0;
            memset(coin->smartaddr,0,sizeof(coin->smartaddr));
            if ( bits256_nonz(privkey) == 0 || coin->smartaddr[0] == 0 )
                privkey = LP_privkeycalc(ctx,pubkey33,&pubkey,coin,passphrase,"");
        }
        //printf("i.%d of %d\n",i,LP_numcoins);
        else if ( IAMLP == 0 || coin->inactive == 0 )
        {
            //printf("from updates %s\n",coin->symbol);
            if ( LP_privkey_init(pubsock,coin,G.LP_privkey,G.LP_mypub25519) == 0 && (rand() % 10) == 0 )
                LP_postutxos(coin->symbol,coin->smartaddr);
        }
    }
}

int32_t LP_passphrase_init(char *passphrase,char *gui)
{
    static void *ctx; int32_t iambob,counter; struct LP_utxoinfo *utxo,*tmp;
    if ( ctx == 0 )
        ctx = bitcoin_ctx();
    if ( G.LP_pendingswaps != 0 )
        return(-1);
    G.initializing = 1;
    if ( gui == 0 )
        gui = "cli";
    counter = G.USERPASS_COUNTER;
    while ( G.waiting == 0 )
    {
        printf("waiting for G.waiting\n");
        sleep(5);
    }
    for (iambob=0; iambob<2; iambob++)
    {
        if ( G.LP_utxoinfos[iambob] != 0 )
        {
            HASH_ITER(hh,G.LP_utxoinfos[iambob],utxo,tmp)
            {
                HASH_DELETE(hh,G.LP_utxoinfos[iambob],utxo);
                //free(utxo);
            }
        }
        if ( G.LP_utxoinfos2[iambob] != 0 )
        {
            G.LP_utxoinfos2[iambob] = 0;
            /*HASH_ITER(hh,G.LP_utxoinfos2[iambob],utxo,tmp)
            {
                HASH_DELETE(hh,G.LP_utxoinfos2[iambob],utxo);
                free(utxo);
            }*/
        }
    }
    memset(&G,0,sizeof(G));
    LP_privkey_updates(ctx,LP_mypubsock,passphrase);
    init_hexbytes_noT(G.LP_myrmd160str,G.LP_myrmd160,20);
    G.LP_sessionid = (uint32_t)time(NULL);
    safecopy(G.gui,gui,sizeof(G.gui));
    G.USERPASS_COUNTER = counter;
    return(0);
}


