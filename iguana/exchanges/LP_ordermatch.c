
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
//  LP_ordermatch.c
//  marketmaker
//
struct LP_quoteinfo LP_Alicequery,LP_Alicereserved;
double LP_Alicemaxprice;
bits256 LP_Alicedestpubkey,LP_bobs_reserved;
uint32_t Alice_expiration,Bob_expiration;
struct { uint64_t aliceid; double bestprice; uint32_t starttime,counter; } Bob_competition[512];

double LP_bob_competition(int32_t *counterp,uint64_t aliceid,double price,int32_t counter)
{
    int32_t i,firsti = -1; uint32_t now = (uint32_t)time(NULL);
    *counterp = 0;
    for (i=0; i<sizeof(Bob_competition)/sizeof(*Bob_competition); i++)
    {
        if ( Bob_competition[i].aliceid == aliceid )
        {
            if ( now > Bob_competition[i].starttime+LP_AUTOTRADE_TIMEOUT )
            {
                //printf("aliceid.%llu expired\n",(long long)aliceid);
                Bob_competition[i].bestprice = 0.;
                Bob_competition[i].starttime = now;
                Bob_competition[i].counter = 0;
            }
            if ( price != 0. && (Bob_competition[i].bestprice == 0. || price < Bob_competition[i].bestprice) )
            {
                Bob_competition[i].bestprice = price;
                //printf("Bob competition aliceid.%llu <- bestprice %.8f\n",(long long)aliceid,price);
            }
            Bob_competition[i].counter += counter;
            *counterp = Bob_competition[i].counter;
            return(Bob_competition[i].bestprice);
        }
        else if ( Bob_competition[i].aliceid == 0 )
            firsti = i;
    }
    if ( firsti < 0 )
        firsti = (LP_rand() % (sizeof(Bob_competition)/sizeof(*Bob_competition)));
    Bob_competition[firsti].starttime = (uint32_t)time(NULL);
    Bob_competition[firsti].counter = counter;
    Bob_competition[firsti].aliceid = aliceid;
    Bob_competition[firsti].bestprice = price;
    *counterp = counter;
    //printf("Bob competition aliceid.%llu %.8f\n",(long long)aliceid,price);
    return(price);
}

uint64_t LP_txfeecalc(struct iguana_info *coin,uint64_t txfee,int32_t txlen)
{
    if ( coin != 0 )
    {
        if ( strcmp(coin->symbol,"BTC") == 0 )
        {
            if ( txlen == 0 )
                txlen = LP_AVETXSIZE;
            coin->rate = LP_getestimatedrate(coin);
            if ( (txfee= SATOSHIDEN * coin->rate * txlen) <= LP_MIN_TXFEE )
            {
                coin->rate = -1.;
                coin->rate = _LP_getestimatedrate(coin);
                if ( (txfee= SATOSHIDEN * coin->rate * txlen) <= LP_MIN_TXFEE )
                    txfee = LP_MIN_TXFEE;
            }
        } else txfee = coin->txfee;
        if ( txfee < LP_MIN_TXFEE )
            txfee = LP_MIN_TXFEE;
    }
    return(txfee);
}

double LP_qprice_calc(int64_t *destsatoshisp,int64_t *satoshisp,double price,uint64_t b_satoshis,uint64_t txfee,uint64_t a_value,uint64_t maxdestsatoshis,uint64_t desttxfee)
{
    uint64_t destsatoshis,satoshis;
    a_value -= (desttxfee + 1);
    destsatoshis = ((b_satoshis - txfee) * price);
    if ( destsatoshis > a_value )
        destsatoshis = a_value;
    if ( maxdestsatoshis != 0 && destsatoshis > maxdestsatoshis-desttxfee-1 )
        destsatoshis = maxdestsatoshis-desttxfee-1;
    satoshis = (destsatoshis / price + 0.49) - txfee;
    *destsatoshisp = destsatoshis;
    *satoshisp = satoshis;
    if ( satoshis > 0 )
        return((double)destsatoshis / satoshis);
    else return(0.);
}

int32_t LP_quote_checkmempool(struct LP_quoteinfo *qp,struct LP_utxoinfo *autxo,struct LP_utxoinfo *butxo)
{
    int32_t selector,spendvini; bits256 spendtxid;
    if ( butxo != 0 && (selector= LP_mempool_vinscan(&spendtxid,&spendvini,qp->srccoin,qp->coinaddr,qp->txid,qp->vout,qp->txid2,qp->vout2)) >= 0 )
    {
        char str[65]; printf("LP_tradecommand selector.%d in mempool %s vini.%d",selector,bits256_str(str,spendtxid),spendvini);
        return(-1);
    }
    if ( autxo != 0 && (selector= LP_mempool_vinscan(&spendtxid,&spendvini,qp->destcoin,qp->destaddr,qp->desttxid,qp->destvout,qp->feetxid,qp->feevout)) >= 0 )
    {
        char str[65]; printf("LP_tradecommand dest selector.%d in mempool %s vini.%d",selector,bits256_str(str,spendtxid),spendvini);
        return(-1);
    }
    return(0);
}

double LP_quote_validate(struct LP_utxoinfo *autxo,struct LP_utxoinfo *butxo,struct LP_quoteinfo *qp,int32_t iambob)
{
    double qprice=0.; char str[65]; cJSON *txout; uint64_t txfee,desttxfee,srcvalue=0,srcvalue2=0,destvalue=0,destvalue2=0;
    //printf(">>>>>>> quote satoshis.(%.8f %.8f) %s %.8f -> %s %.8f\n",dstr(qp->satoshis),dstr(qp->destsatoshis),qp->srccoin,dstr(qp->satoshis),qp->destcoin,dstr(qp->destsatoshis));
    if ( butxo != 0 )
    {
        if ( LP_iseligible(&srcvalue,&srcvalue2,1,qp->srccoin,qp->txid,qp->vout,qp->satoshis,qp->txid2,qp->vout2) == 0 )
        {
            //printf("bob not eligible %s (%.8f %.8f)\n",jprint(LP_quotejson(qp),1),dstr(srcvalue),dstr(srcvalue2));
            return(-2);
        }
        if ( (txout= LP_gettxout(qp->srccoin,qp->coinaddr,qp->txid,qp->vout)) != 0 )
            free_json(txout);
        else
        {
            printf("%s %s payment %s/v%d is spent\n",qp->srccoin,qp->coinaddr,bits256_str(str,qp->txid),qp->vout);
            return(-21);
        }
        if ( (txout= LP_gettxout(qp->srccoin,qp->coinaddr,qp->txid2,qp->vout2)) != 0 )
            free_json(txout);
        else
        {
            printf("%s %s deposit %s/v%d is spent\n",qp->srccoin,qp->coinaddr,bits256_str(str,qp->txid2),qp->vout2);
            return(-22);
        }
        if ( bits256_cmp(butxo->deposit.txid,qp->txid2) != 0 || butxo->deposit.vout != qp->vout2 )
        {
            char str[65],str2[65]; printf("%s != %s v%d != %d\n",bits256_str(str,butxo->deposit.txid),bits256_str(str2,qp->txid2),butxo->deposit.vout,qp->vout2);
            return(-6);
        }
        if ( strcmp(butxo->coinaddr,qp->coinaddr) != 0 )
        {
            printf("(%s) != (%s)\n",butxo->coinaddr,qp->coinaddr);
            return(-7);
        }
    }
    if ( autxo != 0 )
    {
        if ( LP_iseligible(&destvalue,&destvalue2,0,qp->destcoin,qp->desttxid,qp->destvout,qp->destsatoshis,qp->feetxid,qp->feevout) == 0 )
        {
            //alice not eligible 0.36893923 -> dest 0.55020000 1.49130251 (0.61732249 0.00104324) 14b8b74808d2d34a70e5eddd1cad47d855858f8b23cac802576d4d37b5f8af8f/v1 abec6e76169bcb738235ca67fab02cc55390f39e422aa71f1badf8747c290cc4/v1
            //char str[65],str2[65]; printf("alice not eligible %.8f -> dest %.8f %.8f (%.8f %.8f) %s/v%d %s/v%d\n",dstr(qp->satoshis),dstr(qp->destsatoshis),(double)qp->destsatoshis/qp->satoshis,dstr(destvalue),dstr(destvalue2),bits256_str(str,qp->desttxid),qp->destvout,bits256_str(str2,qp->feetxid),qp->feevout);
            return(-3);
        }
        if ( (txout= LP_gettxout(qp->destcoin,qp->destaddr,qp->desttxid,qp->destvout)) != 0 )
            free_json(txout);
        else
        {
            printf("%s %s Apayment %s/v%d is spent\n",qp->destcoin,qp->destaddr,bits256_str(str,qp->desttxid),qp->destvout);
            return(-23);
        }
        if ( (txout= LP_gettxout(qp->destcoin,qp->destaddr,qp->feetxid,qp->feevout)) != 0 )
            free_json(txout);
        else
        {
            printf("%s %s dexfee %s/v%d is spent\n",qp->destcoin,qp->destaddr,bits256_str(str,qp->feetxid),qp->feevout);
            return(-24);
        }
    }
    if ( LP_quote_checkmempool(qp,autxo,butxo) < 0 )
        return(-4);
    //if ( iambob != 0 && (*butxop= LP_utxofind(1,qp->txid,qp->vout)) == 0 )
    //    return(-5);
    if ( iambob == 0 && autxo != 0 )
    {
        //if ( (*autxop= LP_utxofind(0,qp->desttxid,qp->destvout)) == 0 )
        //    return(-8);
        if ( bits256_cmp(autxo->fee.txid,qp->feetxid) != 0 || autxo->fee.vout != qp->feevout )
            return(-9);
        if ( strcmp(autxo->coinaddr,qp->destaddr) != 0 )
            return(-10);
    }
    if ( autxo != 0 && destvalue < qp->desttxfee+qp->destsatoshis )
    {
        printf("destvalue %.8f  destsatoshis %.8f is too small txfee %.8f?\n",dstr(destvalue),dstr(qp->destsatoshis),dstr(qp->desttxfee));
        return(-11);
    }
    if ( butxo != 0 && srcvalue < qp->txfee+qp->satoshis )
    {
        printf("srcvalue %.8f [%.8f] satoshis %.8f is too small txfee %.8f?\n",dstr(srcvalue),dstr(srcvalue) - dstr(qp->txfee+qp->satoshis),dstr(qp->satoshis),dstr(qp->txfee));
        return(-33);
    }
    if ( qp->satoshis != 0 )
        qprice = ((double)qp->destsatoshis / (qp->satoshis-qp->txfee));
    LP_txfees(&txfee,&desttxfee,qp->srccoin,qp->destcoin);
    if ( txfee < qp->txfee )
        txfee = qp->txfee;
    if ( desttxfee < qp->desttxfee )
        desttxfee = qp->desttxfee;
    //printf("qprice %.8f <- %.8f/%.8f txfees.(%.8f %.8f) vs (%.8f %.8f)\n",qprice,dstr(qp->destsatoshis),dstr(qp->satoshis),dstr(qp->txfee),dstr(qp->desttxfee),dstr(txfee),dstr(desttxfee));
    if ( qp->txfee < LP_REQUIRED_TXFEE*txfee || qp->desttxfee < LP_REQUIRED_TXFEE*desttxfee )
        return(-14);
    if ( butxo != 0 )
    {
        if ( qp->satoshis < (srcvalue / LP_MINVOL) || srcvalue < qp->txfee*LP_MINSIZE_TXFEEMULT )
        {
            printf("utxo payment %.8f is less than %f covered by Q %.8f or <10x txfee %.8f [%d %d]\n",dstr(srcvalue),1./LP_MINVOL,dstr(qp->satoshis),dstr(qp->txfee),qp->satoshis < (srcvalue / LP_MINVOL),srcvalue < qp->txfee*LP_MINSIZE_TXFEEMULT);
            return(-12);
        }
    }
    if ( autxo != 0 )
    {
        if ( qp->destsatoshis < (destvalue / LP_MINCLIENTVOL) || destvalue < qp->desttxfee*LP_MINSIZE_TXFEEMULT )
        {
            printf("destsatoshis %.8f is less than %f of value %.8f or < 10x txfee %.8f\n",dstr(qp->destsatoshis),1./LP_MINCLIENTVOL,dstr(destvalue),dstr(qp->desttxfee));
            return(-13);
        }
    }
    return(qprice);
}

int32_t LP_arrayfind(cJSON *array,bits256 txid,int32_t vout)
{
    int32_t i,n = cJSON_GetArraySize(array); cJSON *item;
    for (i=0; i<n; i++)
    {
        item = jitem(array,i);
        if ( vout == jint(item,"vout") && bits256_cmp(txid,jbits256(item,"txid")) == 0 )
            return(i);
    }
    return(-1);
}

int32_t LP_nanobind(void *ctx,char *pairstr)
{
    int32_t i,r,pairsock = -1; uint16_t mypullport; char bindaddr[128];
    if ( LP_canbind != 0 )
    {
        if ( (pairsock= nn_socket(AF_SP,NN_PAIR)) < 0 )
            printf("error creating utxo->pair\n");
        else
        {
            for (i=0; i<10; i++)
            {
                r = (10000 + (LP_rand() % 50000)) & 0xffff;
                if ( LP_fixed_pairport != 0 )
                    r = LP_fixed_pairport;
                nanomsg_transportname(0,pairstr,LP_myipaddr,r);
                nanomsg_transportname(1,bindaddr,LP_myipaddr,r);
                if ( nn_bind(pairsock,bindaddr) >= 0 )
                {
                    //timeout = 1;
                    //nn_setsockopt(pairsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
                    //nn_setsockopt(pairsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
                    printf("nanobind %s to %d\n",pairstr,pairsock);
                    return(pairsock);
                } else printf("error binding to %s for %s\n",bindaddr,pairstr);
                if ( LP_fixed_pairport != 0 )
                    break;
            }
        }
    } else pairsock = LP_initpublicaddr(ctx,&mypullport,pairstr,"127.0.0.1",0,1);
    return(pairsock);
}

int32_t LP_nearest_utxovalue(struct iguana_info *coin,char *coinaddr,struct LP_address_utxo **utxos,int32_t n,uint64_t targetval)
{
    int32_t i,replacei,bestheight,mini = -1; struct LP_address_utxo *up,*bestup; struct electrum_info *backupep=0,*ep; int64_t dist,bestdist; uint64_t mindist = (1LL << 60);
    if ( (ep= coin->electrum) != 0 )
    {
        if ( (backupep= ep->prev) == 0 )
            backupep = ep;
    }
    //printf("LP_nearest_utxovalue %s utxos[%d] target %.8f\n",coin->symbol,n,dstr(targetval));
    for (i=0; i<n; i++)
    {
        if ( (up= utxos[i]) != 0 )
        {
            dist = (up->U.value - targetval);
            //printf("nearest i.%d target %.8f val %.8f dist %.8f mindist %.8f mini.%d spent.%d\n",i,dstr(targetval),dstr(up->U.value),dstr(dist),dstr(mindist),mini,up->spendheight);
            if ( up->spendheight <= 0 )
            {
                if ( dist >= 0 && dist < mindist )
                {
                    //printf("(%.8f %.8f %.8f).%d ",dstr(up->U.value),dstr(dist),dstr(mindist),mini);
                    mini = i;
                    mindist = dist;
                }
            }
        }
    }
    if ( mini >= 0 && (bestup= utxos[mini]) != 0 )
    {
        bestdist = (bestup->U.value - targetval);
        replacei = -1;
        bestheight = bestup->U.height;
        for (i=0; i<n; i++)
        {
            if ( i != mini && (up= utxos[i]) != 0 )
            {
                dist = (up->U.value - targetval);
                if ( dist > 0 && up->U.height < bestheight )
                {
                    if ( (double)dist/bestdist < sqrt(((double)bestheight - up->U.height)/1000) )
                    {
                        replacei = i;
                        bestheight = up->U.height;
                    } //else printf("almost ratio %.3f dist %.8f vs best %.8f, ht %d vs best ht %d\n",(double)dist/bestdist,dstr(dist),dstr(bestdist),up->U.height,bestheight);
                }
            }
        }
        if ( replacei >= 0 )
        {
            printf("REPLACE bestdist %.8f height %d with dist %.8f height %d\n",dstr(bestdist),bestup->U.height,dstr(utxos[replacei]->U.value - targetval),utxos[replacei]->U.height);
            return(replacei);
        }
    }
    //printf("return mini.%d\n",mini);
    return(mini);
}

void LP_butxo_set(struct LP_utxoinfo *butxo,int32_t iambob,struct iguana_info *coin,struct LP_address_utxo *up,struct LP_address_utxo *up2,int64_t satoshis)
{
    butxo->pubkey = G.LP_mypub25519;
    safecopy(butxo->coin,coin->symbol,sizeof(butxo->coin));
    safecopy(butxo->coinaddr,coin->smartaddr,sizeof(butxo->coinaddr));
    butxo->payment.txid = up->U.txid;
    butxo->payment.vout = up->U.vout;
    butxo->payment.value = up->U.value;
    if ( (butxo->iambob= iambob) != 0 )
    {
        butxo->deposit.txid = up2->U.txid;
        butxo->deposit.vout = up2->U.vout;
        butxo->deposit.value = up2->U.value;
    }
    else
    {
        butxo->fee.txid = up2->U.txid;
        butxo->fee.vout = up2->U.vout;
        butxo->fee.value = up2->U.value;
    }
    butxo->S.satoshis = satoshis;
}

void LP_abutxo_set(struct LP_utxoinfo *autxo,struct LP_utxoinfo *butxo,struct LP_quoteinfo *qp)
{
    if ( butxo != 0 )
    {
        memset(butxo,0,sizeof(*butxo));
        butxo->pubkey = qp->srchash;
        safecopy(butxo->coin,qp->srccoin,sizeof(butxo->coin));
        safecopy(butxo->coinaddr,qp->coinaddr,sizeof(butxo->coinaddr));
        butxo->payment.txid = qp->txid;
        butxo->payment.vout = qp->vout;
        //butxo->payment.value = qp->value;
        butxo->iambob = 1;
        butxo->deposit.txid = qp->txid2;
        butxo->deposit.vout = qp->vout2;
        //butxo->deposit.value = up2->U.value;
        butxo->S.satoshis = qp->satoshis;
    }
    if ( autxo != 0 )
    {
        memset(autxo,0,sizeof(*autxo));
        autxo->pubkey = qp->desthash;
        safecopy(autxo->coin,qp->destcoin,sizeof(autxo->coin));
        safecopy(autxo->coinaddr,qp->destaddr,sizeof(autxo->coinaddr));
        autxo->payment.txid = qp->desttxid;
        autxo->payment.vout = qp->destvout;
        //autxo->payment.value = qp->value;
        autxo->iambob = 0;
        autxo->fee.txid = qp->feetxid;
        autxo->fee.vout = qp->feevout;
        //autxo->deposit.value = up2->U.value;
        autxo->S.satoshis = qp->destsatoshis;
    }
}

uint64_t LP_basesatoshis(double relvolume,double price,uint64_t txfee,uint64_t desttxfee)
{
    //printf("basesatoshis %.8f (rel %.8f / price %.8f)\n",dstr(SATOSHIDEN * ((relvolume) / price) + 2*txfee),relvolume,price);
    if ( relvolume > dstr(desttxfee) && price > SMALLVAL )
        return(SATOSHIDEN * (relvolume / price) + 2*txfee);
    else return(0);
}

struct LP_utxoinfo *LP_address_myutxopair(struct LP_utxoinfo *butxo,int32_t iambob,struct LP_address_utxo **utxos,int32_t max,struct iguana_info *coin,char *coinaddr,uint64_t txfee,double relvolume,double price,uint64_t desttxfee)
{
    struct LP_address *ap; uint64_t fee,targetval,targetval2; int32_t m,mini; struct LP_address_utxo *up,*up2; double ratio;
    memset(butxo,0,sizeof(*butxo));
    if ( iambob != 0 )
    {
        targetval = LP_basesatoshis(relvolume,price,txfee,desttxfee);
        targetval2 = (targetval / 8) * 9 + 2*txfee;
        fee = txfee;
        ratio = LP_MINVOL;
    }
    else
    {
        targetval = relvolume*SATOSHIDEN + 2*desttxfee;
        targetval2 = (targetval / 777) + 2*desttxfee;
        fee = desttxfee;
        ratio = LP_MINCLIENTVOL;
    }
    if ( coin != 0 && (ap= LP_address(coin,coinaddr)) != 0 )
    {
        if ( (m= LP_address_utxo_ptrs(coin,iambob,utxos,max,ap,coinaddr)) > 1 )
        {
            if ( 1 )
            {
                int32_t i;
                for (i=0; i<m; i++)
                    if ( utxos[i]->U.value >= targetval )
                        printf("%.8f ",dstr(utxos[i]->U.value));
                printf("targetval %.8f vol %.8f price %.8f txfee %.8f %s %s\n",dstr(targetval),relvolume,price,dstr(txfee),coin->symbol,coinaddr);
            }
            mini = -1;
            if ( targetval != 0 && (mini= LP_nearest_utxovalue(coin,coinaddr,utxos,m,targetval+fee)) >= 0 )
            {
                up = utxos[mini];
                utxos[mini] = 0;
printf("found mini.%d %.8f for targetval %.8f -> targetval2 %.8f, ratio %.2f\n",mini,dstr(up->U.value),dstr(targetval),dstr(targetval2),(double)up->U.value/targetval);
                if ( (double)up->U.value/targetval < ratio-1 )

                {
                    if ( (mini= LP_nearest_utxovalue(coin,coinaddr,utxos,m,(targetval2+2*fee) * 1.01)) >= 0 )
                    {
                        if ( up != 0 && (up2= utxos[mini]) != 0 )
                        {
                            LP_butxo_set(butxo,iambob,coin,up,up2,targetval);
                            return(butxo);
                        }
                    } else printf("cant find targetval2 %.8f\n",dstr(targetval2));
                } else printf("failed ratio test %.8f\n",(double)up->U.value/targetval);
            } else if ( targetval != 0 && mini >= 0 )
                printf("targetval %.8f mini.%d\n",dstr(targetval),mini);
        } else printf("no %s utxos pass LP_address_utxo_ptrs filter\n",coinaddr);
    } else printf("address_myutxopair couldnt find %s %s\n",coin->symbol,coinaddr);
    return(0);
}

int32_t LP_connectstartbob(void *ctx,int32_t pubsock,cJSON *argjson,char *base,char *rel,double price,struct LP_quoteinfo *qp)
{
    char pairstr[512]; cJSON *retjson; bits256 privkey; int32_t pair=-1,retval = -1,DEXselector = 0; struct basilisk_swap *swap; struct iguana_info *coin;
    printf("LP_connectstartbob.(%s) with.(%s) %s\n",LP_myipaddr,jprint(argjson,0),LP_myipaddr);
    qp->quotetime = (uint32_t)time(NULL);
    if ( (coin= LP_coinfind(qp->srccoin)) == 0 )
    {
        printf("cant find coin.%s\n",qp->srccoin);
        return(-1);
    }
    privkey = LP_privkey(coin->smartaddr,coin->taddr);
    if ( bits256_nonz(privkey) != 0 && bits256_cmp(G.LP_mypub25519,qp->srchash) == 0 )
    {
        LP_requestinit(&qp->R,qp->srchash,qp->desthash,base,qp->satoshis-qp->txfee,rel,qp->destsatoshis-qp->desttxfee,qp->timestamp,qp->quotetime,DEXselector);
        if ( LP_pendingswap(qp->R.requestid,qp->R.quoteid) > 0 )
        {
            printf("requestid.%u quoteid.%u is already in progres\n",qp->R.requestid,qp->R.quoteid);
            return(-1);
        }
        if ( (swap= LP_swapinit(1,0,privkey,&qp->R,qp,LP_dynamictrust(qp->desthash,LP_kmdvalue(qp->destcoin,qp->destsatoshis)) > 0)) == 0 )
        {
            printf("cant initialize swap\n");
            return(-1);
        }
        if ( (pair= LP_nanobind(ctx,pairstr)) >= 0 )
        {
            swap->N.pair = pair;
            //utxo->S.swap = swap;
            //swap->utxo = utxo;
            if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)LP_bobloop,(void *)swap) == 0 )
            {
                retjson = LP_quotejson(qp);
                jaddstr(retjson,"method","connected");
                jaddstr(retjson,"pair",pairstr);
                char str[65]; printf("BOB pubsock.%d binds to %d (%s)\n",pubsock,pair,bits256_str(str,qp->desthash));
                LP_reserved_msg(1,base,rel,qp->desthash,jprint(retjson,0));
                sleep(1);
                bits256 zero;
                memset(zero.bytes,0,sizeof(zero));
                LP_reserved_msg(1,base,rel,zero,jprint(retjson,0));
                free_json(retjson);
                retval = 0;
            } else printf("error launching swaploop\n");
        } else printf("couldnt bind to any port %s\n",pairstr);
    }
    if ( retval < 0 )
    {
        if ( pair >= 0 )
            nn_close(pair);
        LP_availableset(qp->txid,qp->vout);
        LP_availableset(qp->txid2,qp->vout2);
    }
    return(retval);
}

char *LP_trade(void *ctx,char *myipaddr,int32_t mypubsock,struct LP_quoteinfo *qp,double maxprice,int32_t timeout,int32_t duration,uint32_t tradeid,bits256 destpubkey)
{
    struct LP_utxoinfo *aliceutxo; double price;
    if ( (aliceutxo= LP_utxopairfind(0,qp->desttxid,qp->destvout,qp->feetxid,qp->feevout)) == 0 )
    {
        char str[65],str2[65]; printf("dest.(%s)/v%d fee.(%s)/v%d\n",bits256_str(str,qp->desttxid),qp->destvout,bits256_str(str2,qp->feetxid),qp->feevout);
        return(clonestr("{\"error\":\"cant find alice utxopair\"}"));
    }
    price = 0.;
    memset(qp->txid.bytes,0,sizeof(qp->txid));
    qp->txid2 = qp->txid;
    qp->aliceid = LP_aliceid_calc(qp->desttxid,qp->destvout,qp->feetxid,qp->feevout);
    if ( (qp->tradeid= tradeid) == 0 )
        qp->tradeid = LP_rand();
    LP_query(ctx,myipaddr,mypubsock,"request",qp);
    LP_Alicequery = *qp, LP_Alicemaxprice = maxprice, Alice_expiration = qp->timestamp + timeout, LP_Alicedestpubkey = destpubkey;
    char str[65]; printf("LP_trade %s/%s %.8f vol %.8f dest.(%s) maxprice %.8f\n",qp->srccoin,qp->destcoin,dstr(qp->satoshis),dstr(qp->destsatoshis),bits256_str(str,LP_Alicedestpubkey),maxprice);
    return(LP_recent_swaps(0));
}

int32_t LP_quotecmp(int32_t strictflag,struct LP_quoteinfo *qp,struct LP_quoteinfo *qp2)
{
    if ( bits256_nonz(LP_Alicedestpubkey) != 0 )
    {
        if (bits256_cmp(LP_Alicedestpubkey,qp->srchash) != 0 )
        {
            printf("reject quote from non-matching pubkey\n");
            return(-1);
        } else printf("dont reject quote from destpubkey\n");
    }
    if ( bits256_cmp(qp->desthash,qp2->desthash) == 0 && strcmp(qp->srccoin,qp2->srccoin) == 0 && strcmp(qp->destcoin,qp2->destcoin) == 0 && bits256_cmp(qp->desttxid,qp2->desttxid) == 0 && qp->destvout == qp2->destvout && bits256_cmp(qp->feetxid,qp2->feetxid) == 0 && qp->feevout == qp2->feevout && qp->destsatoshis == qp2->destsatoshis && qp->txfee >= qp2->txfee && qp->desttxfee == qp2->desttxfee )
    {
        if ( strictflag == 0 || (qp->aliceid == qp2->aliceid && qp->R.requestid == qp2->R.requestid && qp->R.quoteid == qp2->R.quoteid && qp->vout == qp2->vout && qp->vout2 == qp2->vout2 && qp->satoshis == qp2->satoshis && bits256_cmp(qp->txid,qp2->txid) == 0 && bits256_cmp(qp->txid2,qp2->txid2) == 0 && bits256_cmp(qp->srchash,qp2->srchash) == 0) )
            return(0);
        else printf("strict compare failure\n");
    }
    return(-1);
}

void LP_alicequery_clear()
{
    memset(&LP_Alicequery,0,sizeof(LP_Alicequery));
    memset(&LP_Alicedestpubkey,0,sizeof(LP_Alicedestpubkey));
    LP_Alicemaxprice = 0.;
    Alice_expiration = 0;
}

int32_t LP_alice_eligible(uint32_t quotetime)
{
    if ( Alice_expiration != 0 && quotetime > Alice_expiration )
    {
        printf("time expired for Alice_request\n");
        LP_alicequery_clear();
    }
    return(Alice_expiration == 0 || time(NULL) < Alice_expiration);
}

void LP_reserved(void *ctx,char *myipaddr,int32_t mypubsock,struct LP_quoteinfo *qp)
{
    double price=0.,maxprice = LP_Alicemaxprice;
    if ( LP_quotecmp(0,qp,&LP_Alicequery) == 0 )
    {
        price = LP_pricecache(qp,qp->srccoin,qp->destcoin,qp->txid,qp->vout);
        if ( LP_pricevalid(price) > 0 && maxprice > SMALLVAL && price <= maxprice )
        {
            qp->tradeid = LP_Alicequery.tradeid;
            LP_Alicereserved = *qp;
            LP_alicequery_clear();
            printf("send CONNECT\n");
            LP_query(ctx,myipaddr,mypubsock,"connect",qp);
        } else printf("LP_reserved price %.8f vs maxprice %.8f\n",price,maxprice*1.005);
    } else printf("probably a timeout, reject reserved due to not eligible.%d or mismatched quote price %.8f vs maxprice %.8f\n",LP_alice_eligible(qp->quotetime),price,maxprice);
}

char *LP_connectedalice(cJSON *argjson) // alice
{
    cJSON *retjson; double bid,ask,price,qprice; int32_t pairsock = -1; char *pairstr; int32_t DEXselector = 0; struct LP_utxoinfo *autxo,A,B,*butxo; struct LP_quoteinfo Q; struct basilisk_swap *swap; struct iguana_info *coin;
    if ( LP_quoteparse(&Q,argjson) < 0 )
    {
        LP_aliceid(Q.tradeid,Q.aliceid,"error0",0,0);
        clonestr("{\"error\":\"cant parse quote\"}");
    }
    if ( bits256_cmp(Q.desthash,G.LP_mypub25519) != 0 )
    {
        LP_aliceid(Q.tradeid,Q.aliceid,"error1",0,0);
        return(clonestr("{\"result\",\"update stats\"}"));
    }
  printf("CONNECTED.(%s) numpending.%d tradeid.%u requestid.%u quoteid.%u\n",jprint(argjson,0),G.LP_pendingswaps,Q.tradeid,Q.R.requestid,Q.R.quoteid);
    LP_requestinit(&Q.R,Q.srchash,Q.desthash,Q.srccoin,Q.satoshis-Q.txfee,Q.destcoin,Q.destsatoshis-Q.desttxfee,Q.timestamp,Q.quotetime,DEXselector);
    printf("calculated requestid.%u quoteid.%u\n",Q.R.requestid,Q.R.quoteid);
    if ( LP_pendingswap(Q.R.requestid,Q.R.quoteid) > 0 )
    {
        printf("requestid.%u quoteid.%u is already in progres\n",Q.R.requestid,Q.R.quoteid);
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"error","swap already in progress");
        return(jprint(retjson,1));
    }
    if ( LP_quotecmp(1,&Q,&LP_Alicereserved) == 0 )
    {
        printf("mismatched between reserved and connected\n");
    }
    memset(&LP_Alicereserved,0,sizeof(LP_Alicereserved));
    LP_aliceid(Q.tradeid,Q.aliceid,"connected",Q.R.requestid,Q.R.quoteid);
    autxo = &A;
    butxo = &B;
    memset(autxo,0,sizeof(*autxo));
    memset(butxo,0,sizeof(*butxo));
    LP_abutxo_set(autxo,butxo,&Q);
    if ( (qprice= LP_quote_validate(autxo,butxo,&Q,0)) <= SMALLVAL )
    {
        LP_availableset(Q.desttxid,Q.vout);
        LP_availableset(Q.feetxid,Q.feevout);
        LP_aliceid(Q.tradeid,Q.aliceid,"error4",0,0);
        printf("quote validate error %.0f\n",qprice);
        return(clonestr("{\"error\":\"quote validation error\"}"));
    }
    if ( LP_myprice(&bid,&ask,Q.srccoin,Q.destcoin) <= SMALLVAL || bid <= SMALLVAL )
    {
        printf("this node has no price for %s/%s (%.8f %.8f)\n",Q.destcoin,Q.srccoin,bid,ask);
        LP_availableset(Q.desttxid,Q.vout);
        LP_availableset(Q.feetxid,Q.feevout);
        LP_aliceid(Q.tradeid,Q.aliceid,"error5",0,0);
        return(clonestr("{\"error\":\"no price set\"}"));
    }
    //LP_RTmetrics_update(Q.srccoin,Q.destcoin);
    printf("%s/%s bid %.8f ask %.8f values %.8f %.8f\n",Q.srccoin,Q.destcoin,bid,ask,dstr(butxo->payment.value),dstr(butxo->deposit.value));
    price = bid;
    if ( (coin= LP_coinfind(Q.destcoin)) == 0 )
    {
        LP_aliceid(Q.tradeid,Q.aliceid,"error6",0,0);
        return(clonestr("{\"error\":\"cant get alicecoin\"}"));
    }
    Q.privkey = LP_privkey(Q.destaddr,coin->taddr);
    if ( bits256_nonz(Q.privkey) != 0 )//&& Q.quotetime >= Q.timestamp-3 )
    {
        retjson = cJSON_CreateObject();
        if ( (swap= LP_swapinit(0,0,Q.privkey,&Q.R,&Q,LP_dynamictrust(Q.srchash,LP_kmdvalue(Q.srccoin,Q.satoshis)) > 0)) == 0 )
        {
            jaddstr(retjson,"error","couldnt swapinit");
            LP_availableset(Q.desttxid,Q.vout);
            LP_availableset(Q.feetxid,Q.feevout);
            LP_aliceid(Q.tradeid,Q.aliceid,"error7",Q.R.requestid,Q.R.quoteid);
            return(jprint(retjson,1));
        }
        if ( (pairstr= jstr(argjson,"pair")) == 0 || (pairsock= nn_socket(AF_SP,NN_PAIR)) < 0 )
        {
            LP_aliceid(Q.tradeid,Q.aliceid,"error8",Q.R.requestid,Q.R.quoteid);
            jaddstr(retjson,"error","couldnt create pairsock");
        }
        else if ( nn_connect(pairsock,pairstr) >= 0 )
        {
            //timeout = 1;
            //nn_setsockopt(pairsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
            //nn_setsockopt(pairsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
            swap->tradeid = Q.tradeid;
            swap->N.pair = pairsock;
            //autxo->S.swap = swap;
            //swap->utxo = autxo;
            LP_aliceid(Q.tradeid,Q.aliceid,"started",Q.R.requestid,Q.R.quoteid);
            printf("alice pairstr.(%s) pairsock.%d\n",pairstr,pairsock);
            if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)LP_aliceloop,(void *)swap) == 0 )
            {
                retjson = LP_quotejson(&Q);
                jaddstr(retjson,"result","success");
                //jaddnum(retjson,"requestid",Q.R.requestid);
                //jaddnum(retjson,"quoteid",Q.R.quoteid);
            }
            else
            {
                LP_aliceid(Q.tradeid,Q.aliceid,"error9",Q.R.requestid,Q.R.quoteid);
                jaddstr(retjson,"error","couldnt aliceloop");
            }
        }
        else
        {
            LP_aliceid(Q.tradeid,Q.aliceid,"error10",Q.R.requestid,Q.R.quoteid);
            printf("connect error %s\n",nn_strerror(nn_errno()));
        }
        printf("connected result.(%s)\n",jprint(retjson,0));
        if ( jobj(retjson,"error") != 0 )
        {
            LP_availableset(Q.desttxid,Q.vout);
            LP_availableset(Q.feetxid,Q.feevout);
        }
        return(jprint(retjson,1));
    }
    else
    {
        LP_availableset(Q.desttxid,Q.vout);
        LP_availableset(Q.feetxid,Q.feevout);
        LP_aliceid(Q.tradeid,Q.aliceid,"error11",0,0);
        printf("no privkey found coin.%s %s taddr.%u\n",Q.destcoin,Q.destaddr,coin->taddr);
        return(clonestr("{\"error\",\"no privkey\"}"));
    }
}

int32_t LP_listunspent_both(char *symbol,char *coinaddr,int32_t fullflag)
{
    int32_t i,v,numconfs,height,n=0; uint64_t value; bits256 txid; char buf[512]; cJSON *array,*item; uint32_t now; struct iguana_info *coin = LP_coinfind(symbol);
    if ( coin != 0 )//&& (IAMLP != 0 || coin->inactive == 0) )
    {
        if ( coin->electrum != 0 || LP_address_ismine(symbol,coinaddr) <= 0 )
        {
            //printf("issue path electrum.%p\n",coin->electrum);
            //if ( coin->electrum != 0 && (array= electrum_address_gethistory(symbol,coin->electrum,&array,coinaddr)) != 0 )
            //    free_json(array);
            n = LP_listunspent_issue(symbol,coinaddr,fullflag);
        }
        else
        {
            if ( strcmp(symbol,"BTC") == 0 )
                numconfs = 0;
            else numconfs = 1;
            //printf("my coin electrum.%p\n",coin->electrum);
            sprintf(buf,"[%d, 99999999, [\"%s\"]]",numconfs,coinaddr);
            if ( (array= bitcoin_json(coin,"listunspent",buf)) != 0 )
            {
                if ( (n= cJSON_GetArraySize(array)) > 0 )
                {
                    now = (uint32_t)time(NULL);
                    for (i=0; i<n; i++)
                    {
                        item = jitem(array,i);
                        txid = jbits256(item,"txid");
                        v = jint(item,"vout");
                        value = LP_value_extract(item,0);
                        height = LP_txheight(coin,txid);
                        //char str[65]; printf("LP_listunspent_both: %s/v%d ht.%d %.8f\n",bits256_str(str,txid),v,height,dstr(value));
                        LP_address_utxoadd(now,"LP_listunspent_both",coin,coinaddr,txid,v,value,height,-1);
                    }
                }
                free_json(array);
            }
        }
    } //else printf("%s coin.%p inactive.%d\n",symbol,coin,coin!=0?coin->inactive:-1);
    return(n);
}

char *LP_bestfit(char *rel,double relvolume)
{
    struct LP_utxoinfo *autxo;
    if ( relvolume <= 0. || LP_priceinfofind(rel) == 0 )
        return(clonestr("{\"error\":\"invalid parameter\"}"));
    if ( (autxo= LP_utxo_bestfit(rel,SATOSHIDEN * relvolume)) == 0 )
        return(clonestr("{\"error\":\"cant find utxo that is close enough in size\"}"));
    return(jprint(LP_utxojson(autxo),1));
}

int32_t LP_aliceonly(char *symbol)
{
    if ( strcmp(symbol,"GAME") == 0 )
        return(1);
    else return(0);
}

int32_t LP_validSPV(char *symbol,char *coinaddr,bits256 txid,int32_t vout)
{
    struct electrum_info *ep,*backupep; cJSON *txobj; struct LP_address_utxo *up; struct iguana_info *coin; struct LP_transaction *tx;
    coin = LP_coinfind(symbol);
    if ( coin != 0 && (ep= coin->electrum) != 0 )
    {
        if ( (up= LP_address_utxofind(coin,coinaddr,txid,vout)) == 0 )
        {
            if ( (txobj= electrum_transaction(symbol,ep,&txobj,txid,coinaddr)) != 0 )
                free_json(txobj);
            if ( (tx= LP_transactionfind(coin,txid)) != 0 )
            {
                if ( vout < tx->numvouts && tx->height > 0 )
                {
                    printf("added missing utxo for SPV checking\n");
                    LP_address_utxoadd((uint32_t)time(NULL),"LP_validSPV",coin,coinaddr,txid,vout,tx->outpoints[vout].value,tx->height,-1);
                }
            }
        }
        if ( (up= LP_address_utxofind(coin,coinaddr,txid,vout)) != 0 )
        {
            if ( up->SPV < 0 )
                return(-1);
            if ( (backupep= ep->prev) == 0 )
                backupep = ep;
            up->SPV = LP_merkleproof(coin,coinaddr,backupep,up->U.txid,up->U.height);
            if ( up->SPV <= 0 )
                return(-1);
        }
    }
    return(0);
}

int32_t LP_tradecommand(void *ctx,char *myipaddr,int32_t pubsock,cJSON *argjson,uint8_t *data,int32_t datalen)
{
    char *method,*msg,*retstr,str[65]; int32_t DEXselector = 0; uint64_t aliceid; cJSON *retjson; double qprice,range,bestprice,price,bid,ask; struct LP_utxoinfo A,B,*autxo,*butxo; struct iguana_info *coin; struct LP_address_utxo *utxos[1000]; struct LP_quoteinfo Q; int32_t r,counter,retval = -1,max=(int32_t)(sizeof(utxos)/sizeof(*utxos));
    if ( (method= jstr(argjson,"method")) != 0 && (strcmp(method,"reserved") == 0 ||strcmp(method,"connected") == 0 || strcmp(method,"request") == 0 || strcmp(method,"connect") == 0) )
    {
        // LP_checksig
        LP_quoteparse(&Q,argjson);
        LP_requestinit(&Q.R,Q.srchash,Q.desthash,Q.srccoin,Q.satoshis-Q.txfee,Q.destcoin,Q.destsatoshis-Q.desttxfee,Q.timestamp,Q.quotetime,DEXselector);
        LP_tradecommand_log(argjson);
        printf("(%-10u %10u) %12s aliceid.%22llu %5s/%-5s %12.8f -> %12.8f price %12.8f | RT.%d %d\n",Q.R.requestid,Q.R.quoteid,method,(long long)Q.aliceid,Q.srccoin,Q.destcoin,dstr(Q.satoshis),dstr(Q.destsatoshis),(double)Q.destsatoshis/Q.satoshis,LP_RTcount,LP_swapscount);
        retval = 1;
        autxo = &A;
        butxo = &B;
        memset(autxo,0,sizeof(*autxo));
        memset(butxo,0,sizeof(*butxo));
        LP_abutxo_set(autxo,butxo,&Q);
        aliceid = j64bits(argjson,"aliceid");
        qprice = jdouble(argjson,"price");
        if ( strcmp(method,"reserved") == 0 )
        {
            bestprice = LP_bob_competition(&counter,aliceid,qprice,1);
            //printf("%s lag %ld: aliceid.%llu price %.8f -> bestprice %.8f Alice max %.8f\n",jprint(argjson,0),Q.quotetime - (time(NULL)-20),(long long)aliceid,qprice,bestprice,LP_Alicemaxprice);
            if ( LP_Alicemaxprice == 0. )
                return(retval);
            if ( bits256_nonz(LP_Alicedestpubkey) != 0 )
            {
                if (bits256_cmp(LP_Alicedestpubkey,Q.srchash) != 0 )
                {
                    printf("got reserved response from different node %s\n",bits256_str(str,Q.srchash));
                    return(retval);
                } else printf("got reserved response from destpubkey %s\n",bits256_str(str,Q.srchash));
            }
            if ( bits256_cmp(G.LP_mypub25519,Q.desthash) == 0 && bits256_cmp(G.LP_mypub25519,Q.srchash) != 0 && Q.quotetime > time(NULL)-20 && LP_alice_eligible(Q.quotetime) > 0 )
            {
                printf("alice %s received RESERVED.(%s)\n",bits256_str(str,G.LP_mypub25519),jprint(argjson,0));
                if ( (qprice= LP_quote_validate(autxo,butxo,&Q,0)) <= SMALLVAL )
                {
                    printf("reserved quote validate error %.0f\n",qprice);
                    return(retval);
                }
                if ( LP_validSPV(Q.srccoin,Q.coinaddr,Q.txid,Q.vout) < 0 )
                {
                    printf("%s src %s failed SPV check\n",Q.srccoin,bits256_str(str,Q.txid));
                    return(retval);
                }
                else if ( LP_validSPV(Q.srccoin,Q.coinaddr,Q.txid2,Q.vout2) < 0 )
                {
                    printf("%s src2 %s failed SPV check\n",Q.srccoin,bits256_str(str,Q.txid2));
                    return(retval);
                }
                LP_aliceid(Q.tradeid,Q.aliceid,"reserved",0,0);
                if ( (retstr= LP_quotereceived(argjson)) != 0 )
                    free(retstr);
                LP_reserved(ctx,myipaddr,pubsock,&Q);
            }
            return(retval);
        }
        else if ( strcmp(method,"connected") == 0 )
        {
            bestprice = LP_bob_competition(&counter,aliceid,qprice,1000);
            if ( bits256_cmp(G.LP_mypub25519,Q.desthash) == 0 && bits256_cmp(G.LP_mypub25519,Q.srchash) != 0 )
            {
                if ( (qprice= LP_quote_validate(autxo,butxo,&Q,0)) <= SMALLVAL )
                {
                    printf("quote validate error %.0f\n",qprice);
                    return(retval);
                }
                if ( LP_validSPV(Q.srccoin,Q.coinaddr,Q.txid,Q.vout) < 0 )
                {
                    printf("%s src %s failed SPV check\n",Q.srccoin,bits256_str(str,Q.txid));
                    return(retval);
                }
                else if (LP_validSPV(Q.srccoin,Q.coinaddr,Q.txid2,Q.vout2) < 0 )
                {
                    printf("%s src2 %s failed SPV check\n",Q.srccoin,bits256_str(str,Q.txid2));
                    return(retval);
                }
               //printf("alice %s received CONNECTED.(%s)\n",bits256_str(str,G.LP_mypub25519),jprint(argjson,0));
                if ( (retstr= LP_connectedalice(argjson)) != 0 )
                    free(retstr);
            }
            return(retval);
        }
        price = LP_myprice(&bid,&ask,Q.srccoin,Q.destcoin);
        if ( (coin= LP_coinfind(Q.srccoin)) == 0 || price <= SMALLVAL || ask <= SMALLVAL )
        {
            //printf("this node has no price for %s/%s\n",Q.srccoin,Q.destcoin);
            return(retval);
        }
        price = ask;
        //printf("MYPRICE %s/%s %.8f vs qprice %.8f\n",Q.srccoin,Q.destcoin,price,qprice);
        if ( LP_validSPV(Q.destcoin,Q.destaddr,Q.desttxid,Q.destvout) < 0 )
        {
            printf("%s dest %s failed SPV check\n",Q.destcoin,bits256_str(str,Q.desttxid));
            return(retval);
        }
        else if (LP_validSPV(Q.destcoin,Q.destaddr,Q.feetxid,Q.feevout) < 0 )
        {
            printf("%s dexfee %s failed SPV check\n",Q.destcoin,bits256_str(str,Q.feetxid));
            return(retval);
        }
        if ( LP_aliceonly(Q.srccoin) > 0 )
        {
            printf("{\"error\":\"GAME can only be alice coin\"}\n");
            return(retval);
        }
        if ( strcmp(method,"request") == 0 )
        {
            char str[65];
            if ( bits256_nonz(Q.srchash) == 0 || bits256_cmp(Q.srchash,G.LP_mypub25519) == 0 )
            {
                qprice = (double)Q.destsatoshis / Q.satoshis;
                strcpy(Q.gui,G.gui);
                strcpy(Q.coinaddr,coin->smartaddr);
                strcpy(butxo->coinaddr,coin->smartaddr);
                Q.srchash = G.LP_mypub25519;
                memset(&Q.txid,0,sizeof(Q.txid));
                memset(&Q.txid2,0,sizeof(Q.txid2));
                Q.vout = Q.vout2 = -1;
            } else return(retval);
            if ( qprice > price )
            {
                r = (LP_rand() % 100);
                range = (qprice - price);
                price += (r * range) / 100.;
                bestprice = LP_bob_competition(&counter,aliceid,price,0);
                printf(">>>>>>>>>>>>> price %.8f qprice %.8f r.%d range %.8f -> %.8f, bestprice %.8f counter.%d\n",ask,qprice,r,range,price,bestprice,counter);
                if ( counter > 3 || price > bestprice ) // skip if late or bad price
                    return(retval);
            } else return(retval);
            //LP_RTmetrics_update(Q.srccoin,Q.destcoin);
            if ( LP_RTmetrics_blacklisted(Q.desthash) >= 0 )
            {
                printf("request from blacklisted %s, ignore\n",bits256_str(str,Q.desthash));
                return(retval);
            }
            LP_address_utxo_reset(coin);
            if ( (butxo= LP_address_myutxopair(butxo,1,utxos,max,LP_coinfind(Q.srccoin),Q.coinaddr,Q.txfee,dstr(Q.destsatoshis),price,Q.desttxfee)) != 0 )
            {
                strcpy(Q.gui,G.gui);
                strcpy(Q.coinaddr,coin->smartaddr);
                Q.srchash = G.LP_mypub25519;
                Q.txid = butxo->payment.txid;
                Q.vout = butxo->payment.vout;
                Q.txid2 = butxo->deposit.txid;
                Q.vout2 = butxo->deposit.vout;
                Q.satoshis = butxo->S.satoshis;
                Q.quotetime = (uint32_t)time(NULL);
                printf("found %.8f -> %.8f newprice %.8f vs ask %.8f += %.8f qprice %.8f\n",dstr(Q.satoshis),dstr(Q.destsatoshis),(double)Q.destsatoshis/Q.satoshis,ask,price,qprice);
            }
            else
            {
                printf("cant find utxopair aliceid.%llu %s/%s %.8f -> relvol %.8f\n",(long long)aliceid,Q.srccoin,Q.destcoin,dstr(LP_basesatoshis(dstr(Q.destsatoshis),price,Q.txfee,Q.desttxfee)),dstr(Q.destsatoshis));
                return(retval);
            }
        }
        else if ( strcmp(method,"connect") == 0 )
        {
            if ( bits256_cmp(G.LP_mypub25519,Q.srchash) != 0 || bits256_cmp(G.LP_mypub25519,Q.desthash) == 0 )
                return(retval);
        }
        if ( strcmp(Q.coinaddr,coin->smartaddr) != 0 )
        {
            printf("bob is patching Q.coinaddr %s mismatch != %s\n",Q.coinaddr,coin->smartaddr);
            strcpy(Q.coinaddr,coin->smartaddr);
        }
        if ( butxo == 0 || bits256_nonz(butxo->payment.txid) == 0 || bits256_nonz(butxo->deposit.txid) == 0 || butxo->payment.vout < 0 || butxo->deposit.vout < 0 )
        {
            char str[65],str2[65]; printf("couldnt find bob utxos for autxo %s/v%d %s/v%d %.8f -> %.8f\n",bits256_str(str,Q.txid),Q.vout,bits256_str(str2,Q.txid2),Q.vout2,dstr(Q.satoshis),dstr(Q.destsatoshis));
            return(retval);
        }
        if ( (qprice= LP_quote_validate(autxo,butxo,&Q,1)) <= SMALLVAL )
        {
            printf("quote validate error %.0f\n",qprice);
            return(-3);
        }
        if ( qprice < (ask - 0.00000001) * 0.998 )
        {
            printf("(%.8f %.8f) quote price %.8f too low vs %.8f for %s/%s %.8f < %.8f\n",bid,ask,qprice,price,Q.srccoin,Q.destcoin,qprice,(ask - 0.00000001) * 0.998);
            return(retval);
        }
        char *astr = jprint(argjson,0);
        char str[65],str2[65]; printf("(%s/v%d %s/v%d) TRADECOMMAND.(%s)\n",bits256_str(str,Q.txid),Q.vout,bits256_str(str2,Q.txid2),Q.vout2,astr);
        free(astr);
        if ( strcmp(method,"request") == 0 ) // bob needs apayment + fee tx's
        {
            if ( LP_allocated(Q.txid,Q.vout) == 0 && LP_allocated(Q.txid2,Q.vout2) == 0 )
            {
                retjson = LP_quotejson(&Q);
                LP_unavailableset(Q.txid,Q.vout,Q.timestamp + LP_RESERVETIME,Q.desthash);
                LP_unavailableset(Q.txid2,Q.vout2,Q.timestamp + LP_RESERVETIME,Q.desthash);
                if ( Q.quotetime == 0 )
                    Q.quotetime = (uint32_t)time(NULL);
                jaddnum(retjson,"quotetime",Q.quotetime);
                jaddnum(retjson,"pending",Q.timestamp + LP_RESERVETIME);
                //jaddbits256(retjson,"desthash",Q.desthash);
                jaddstr(retjson,"method","reserved");
                msg = jprint(retjson,0);
                printf("return after queued RESERVED: set swappending.%u accept qprice %.8f, min %.8f\n(%s)\n",Q.timestamp + LP_RESERVETIME,qprice,ask,msg);
                LP_reserved_msg(1,Q.srccoin,Q.destcoin,Q.desthash,clonestr(msg));
                sleep(1);
                bits256 zero;
                memset(zero.bytes,0,sizeof(zero));
                LP_reserved_msg(1,Q.srccoin,Q.destcoin,zero,msg);
                free_json(retjson);
                butxo->T.lasttime = (uint32_t)time(NULL);
                return(retval);
            } else printf("request processing selected ineligible utxos?\n");
        }
        else if ( strcmp(method,"connect") == 0 ) // bob
        {
            retval = 4;
            if ( LP_reservation_check(Q.txid,Q.vout,Q.desthash) == 0 && LP_reservation_check(Q.txid2,Q.vout2,Q.desthash) == 0  )
            {
                LP_connectstartbob(ctx,pubsock,argjson,Q.srccoin,Q.destcoin,qprice,&Q);
                return(retval);
            } else printf("connect message from non-reserved (%s)\n",jprint(argjson,0));
        }
    }
    return(retval);
}

#ifdef oldway
struct LP_utxoinfo *LP_ordermatch_iter(struct LP_address_utxo **utxos,int32_t max,double *ordermatchpricep,int64_t *bestsatoshisp,int64_t *bestdestsatoshisp,struct iguana_info *basecoin,char *coinaddr,uint64_t asatoshis,double price,uint64_t txfee,uint64_t desttxfee,bits256 pubkey,char *gui)
{
    uint64_t basesatoshis; struct LP_utxoinfo *bestutxo;
    basesatoshis = LP_basesatoshis(dstr(asatoshis),price,txfee,desttxfee);
    //printf("basesatoshis %.8f price %.8f txfee %.8f desttxfee %.8f\n",dstr(basesatoshis),price,dstr(txfee),dstr(desttxfee));
    if ( basesatoshis != 0 && (bestutxo= LP_address_utxopair(0,utxos,max,basecoin,coinaddr,txfee,dstr(basesatoshis)*price,price,desttxfee)) != 0 )
    {
        bestutxo->pubkey = pubkey;
        safecopy(bestutxo->gui,gui,sizeof(bestutxo->gui));
        *bestsatoshisp = basesatoshis;
        *ordermatchpricep = price;
        *bestdestsatoshisp = asatoshis;
        return(bestutxo);
    }
    return(0);
}

struct LP_utxoinfo *LP_buyutxo(double *ordermatchpricep,int64_t *bestsatoshisp,int64_t *bestdestsatoshisp,struct LP_utxoinfo *autxo,char *base,double maxprice,int32_t duration,uint64_t txfee,uint64_t desttxfee,char *gui,bits256 *avoids,int32_t numavoids,bits256 destpubkey)
{
    bits256 pubkey; char *obookstr,coinaddr[64]; cJSON *orderbook,*asks,*rawasks,*item; int32_t maxiters,i,j,numasks,max; struct LP_address_utxo **utxos; double price; struct LP_pubkey_info *pubp; uint64_t asatoshis; struct iguana_info *basecoin; struct LP_utxoinfo *bestutxo = 0;
    maxiters = 100;
    *ordermatchpricep = 0.;
    *bestsatoshisp = *bestdestsatoshisp = 0;
    basecoin = LP_coinfind(base);
    if ( duration <= 0 )
        duration = LP_ORDERBOOK_DURATION;
    if ( maxprice <= 0. || LP_priceinfofind(base) == 0 || basecoin == 0 )
        return(0);
    if ( basecoin->electrum == 0 )
        max = 1000;
    else max = LP_MAXDESIRED_UTXOS;
    utxos = calloc(max,sizeof(*utxos));
    LP_txfees(&txfee,&desttxfee,base,autxo->coin);
    printf("LP_buyutxo maxprice %.8f relvol %.8f %s/%s %.8f %.8f\n",maxprice,dstr(autxo->S.satoshis),base,autxo->coin,dstr(txfee),dstr(desttxfee));
    if ( (obookstr= LP_orderbook(base,autxo->coin,duration)) != 0 )
    {
        if ( (orderbook= cJSON_Parse(obookstr)) != 0 )
        {
            if ( (rawasks= jarray(&numasks,orderbook,"asks")) != 0 )
            {
                if ( (asks= LP_RTmetrics_sort(base,autxo->coin,rawasks,numasks,maxprice,dstr(autxo->S.satoshis))) == 0 )
                    asks = rawasks;
                for (i=0; i<numasks; i++)
                {
                    item = jitem(asks,i);
                    price = jdouble(item,"price");
                    //if ( price < maxprice && price > maxprice*0.8)
                    //    price = price * 0.9 + 0.1 * maxprice;
                    //else price *= 1.005;
                    pubkey = jbits256(item,"pubkey");
                    if ( bits256_nonz(destpubkey) != 0 && bits256_cmp(destpubkey,pubkey) != 0 )
                        continue;
                    if ( LP_RTmetrics_blacklisted(pubkey) >= 0 )
                        continue;
//printf("[%d/%d] %s pubcmp %d price %.8f vs maxprice %.8f asatoshis %.8f\n",i,numasks,jprint(item,0),bits256_cmp(pubkey,G.LP_mypub25519),price,maxprice,dstr(autxo->S.satoshis));
                    if ( LP_pricevalid(price) > 0 && price <= maxprice )
                    {
                        if ( bits256_nonz(destpubkey) == 0 )
                        {
                            for (j=0; j<numavoids; j++)
                                if ( bits256_cmp(pubkey,avoids[j]) == 0 )
                                    break;
                            if ( j != numavoids )
                                continue;
                        }
                        if ( bits256_cmp(pubkey,G.LP_mypub25519) != 0 && (pubp= LP_pubkeyadd(pubkey)) != 0 )
                        {
                            bitcoin_address(coinaddr,basecoin->taddr,basecoin->pubtype,pubp->rmd160,sizeof(pubp->rmd160));
                            asatoshis = autxo->S.satoshis;
                            //LP_listunspent_query(base,coinaddr);
                            for (j=0; j<maxiters; j++)
                            {
                                if ( (bestutxo= LP_ordermatch_iter(utxos,max,ordermatchpricep,bestsatoshisp,bestdestsatoshisp,basecoin,coinaddr,asatoshis,maxprice*.999,txfee,desttxfee,pubp->pubkey,gui)) != 0 )
                                {
                                    //printf("j.%d/%d ordermatch %.8f best satoshis %.8f destsatoshis %.8f txfees (%.8f %.8f)\n",j,maxiters,price,dstr(*bestsatoshisp),dstr(*bestdestsatoshisp),dstr(txfee),dstr(desttxfee));
                                    break;
                                }
                                asatoshis = (asatoshis / 64) * 63;
                            }
                            if ( j < maxiters )
                                break;
                        } else printf("self trading or blacklisted peer\n");
                    }
                    else
                    {
                        if ( i == 0 )
                            printf("too expensive maxprice %.8f vs %.8f\n",maxprice,price);
                        break;
                    }
                }
                if ( asks != 0 && asks != rawasks )
                    free_json(asks);
            }
            free_json(orderbook);
        }
        free(obookstr);
    }
    free(utxos);
    if ( *ordermatchpricep == 0. || *bestdestsatoshisp == 0 )
        return(0);
    int32_t changed;
    LP_mypriceset(&changed,autxo->coin,base,1. / *ordermatchpricep);
    return(bestutxo);
}
#endif

char *LP_autobuy(void *ctx,char *myipaddr,int32_t mypubsock,char *base,char *rel,double maxprice,double relvolume,int32_t timeout,int32_t duration,char *gui,uint32_t nonce,bits256 destpubkey,uint32_t tradeid)
{
    uint64_t desttxfee,txfee; uint32_t lastnonce; int64_t bestsatoshis=0,destsatoshis; struct iguana_info *basecoin,*relcoin; struct LP_utxoinfo *autxo,B,A; struct LP_quoteinfo Q; bits256 pubkeys[100]; struct LP_address_utxo *utxos[1000]; int32_t max=(int32_t)(sizeof(utxos)/sizeof(*utxos));
    basecoin = LP_coinfind(base);
    relcoin = LP_coinfind(rel);
    if ( gui == 0 )
        gui = "nogui";
    if ( basecoin == 0 || basecoin->inactive != 0 || relcoin == 0 || relcoin->inactive != 0 )
        return(clonestr("{\"error\":\"base or rel not found or inactive\"}"));
    if ( LP_aliceonly(base) > 0 )
        return(clonestr("{\"error\":\"GAME can only be alice coin\"}"));
    printf("LP_autobuy %s/%s price %.8f vol %.8f nonce %u\n",base,rel,maxprice,relvolume,nonce);
    if ( (lastnonce= LP_lastnonce) != 0 && nonce <= lastnonce )
    {
        printf("nonce.%u not bigger than lastnonce.%u\n",nonce,lastnonce);
        return(clonestr("{\"error\":\"invalid nonce\"}"));
    }
    LP_lastnonce = nonce;
    if ( duration <= 0 )
        duration = LP_ORDERBOOK_DURATION;
    if ( timeout <= 0 )
        timeout = LP_AUTOTRADE_TIMEOUT;
    if ( basecoin->electrum != 0 && relcoin->electrum != 0 )
    {
        if ( timeout < 2*LP_AUTOTRADE_TIMEOUT )
            timeout = 2*LP_AUTOTRADE_TIMEOUT;
    }
    else if ( basecoin->electrum != 0 || relcoin->electrum != 0 )
    {
        if ( timeout < 1.5*LP_AUTOTRADE_TIMEOUT )
            timeout = 1.5*LP_AUTOTRADE_TIMEOUT;
    }
    if ( time(NULL) < Alice_expiration )
        return(clonestr("{\"error\":\"only one pending request at a time\"}"));
    else LP_alicequery_clear();
    if ( maxprice <= 0. || relvolume <= 0. || LP_priceinfofind(base) == 0 || LP_priceinfofind(rel) == 0 )
        return(clonestr("{\"error\":\"invalid parameter\"}"));
    if ( strcmp("BTC",rel) == 0 )
        maxprice *= 1.01;
    else maxprice *= 1.001;
    memset(pubkeys,0,sizeof(pubkeys));
    LP_txfees(&txfee,&desttxfee,base,rel);
    destsatoshis = SATOSHIDEN * relvolume;
    //LP_address_utxo_reset(relcoin);
    memset(&A,0,sizeof(A));
    LP_address_utxo_reset(relcoin);
    if ( (autxo= LP_address_myutxopair(&A,0,utxos,max,relcoin,relcoin->smartaddr,txfee,dstr(destsatoshis),maxprice,desttxfee)) != 0 )
    //if ( (autxo= LP_utxo_bestfit(rel,destsatoshis + 2*desttxfee)) == 0 )
        return(clonestr("{\"error\":\"cant find alice utxo that is close enough in size\"}"));
    //printf("bestfit selected alice (%.8f %.8f) for %.8f sats %.8f\n",dstr(autxo->payment.value),dstr(autxo->fee.value),dstr(destsatoshis),dstr(autxo->S.satoshis));
    if ( destsatoshis - desttxfee < autxo->S.satoshis )
    {
        destsatoshis -= desttxfee;
        autxo->S.satoshis = destsatoshis;
        //printf("first path dest %.8f from %.8f\n",dstr(destsatoshis),dstr(autxo->S.satoshis));
    }
    else if ( autxo->S.satoshis - desttxfee < destsatoshis )
    {
        autxo->S.satoshis -= desttxfee;
        destsatoshis = autxo->S.satoshis;
        printf("second path dest %.8f from %.8f\n",dstr(destsatoshis),dstr(autxo->S.satoshis));
    }
    if ( destsatoshis < (autxo->payment.value / LP_MINCLIENTVOL) || autxo->payment.value < desttxfee*LP_MINSIZE_TXFEEMULT )
    {
        printf("destsatoshis %.8f vs utxo %.8f this would have triggered an quote error -13\n",dstr(destsatoshis),dstr(autxo->payment.value));
        return(clonestr("{\"error\":\"cant find alice utxo that is small enough\"}"));
    }
    bestsatoshis = 1.001 * LP_basesatoshis(dstr(destsatoshis),maxprice,txfee,desttxfee);
    memset(&B,0,sizeof(B));
    strcpy(B.coin,base);
    if ( LP_quoteinfoinit(&Q,&B,rel,maxprice,bestsatoshis,destsatoshis) < 0 )
        return(clonestr("{\"error\":\"cant set ordermatch quote\"}"));
    if ( LP_quotedestinfo(&Q,autxo->payment.txid,autxo->payment.vout,autxo->fee.txid,autxo->fee.vout,G.LP_mypub25519,autxo->coinaddr) < 0 )
        return(clonestr("{\"error\":\"cant set ordermatch quote info\"}"));
    int32_t changed;
    LP_mypriceset(&changed,autxo->coin,base,1. / maxprice);
    return(LP_trade(ctx,myipaddr,mypubsock,&Q,maxprice,timeout,duration,tradeid,destpubkey));
#ifdef oldway
    //LP_RTmetrics_update(base,rel);
    while ( 1 )
    {
        if ( (bestutxo= LP_buyutxo(&ordermatchprice,&bestsatoshis,&bestdestsatoshis,autxo,base,maxprice,duration,txfee,desttxfee,gui,pubkeys,numpubs,destpubkey)) == 0 || ordermatchprice == 0. || bestdestsatoshis == 0 )
        {
            printf("bestutxo.%p ordermatchprice %.8f bestdestsatoshis %.8f\n",bestutxo,ordermatchprice,dstr(bestdestsatoshis));
            return(clonestr("{\"error\":\"cant find ordermatch utxo, need to change relvolume to be closer to available\"}"));
        }
        pubkeys[numpubs++] = bestutxo->pubkey;
        if ( LP_quoteinfoinit(&Q,bestutxo,rel,ordermatchprice,bestsatoshis,bestdestsatoshis) < 0 )
            return(clonestr("{\"error\":\"cant set ordermatch quote\"}"));
        if ( LP_quotedestinfo(&Q,autxo->payment.txid,autxo->payment.vout,autxo->fee.txid,autxo->fee.vout,G.LP_mypub25519,autxo->coinaddr) < 0 )
            return(clonestr("{\"error\":\"cant set ordermatch quote info\"}"));
        maxiters = 200;
        qprice = 1. / SMALLVAL;
        for (i=0; i<maxiters; i++)
        {
            if ( (qprice= LP_quote_validate(autxo,0,&Q,0)) <= SMALLVAL )
            {
                printf("quote validate error %.0f\n",qprice);
                return(clonestr("{\"error\":\"quote validate error\"}"));
            }
            if ( qprice/ordermatchprice < 1.+SMALLVAL )
            {
                //printf("i.%d/%d qprice %.8f < ordermatchprice %.8f\n",i,maxiters,qprice,ordermatchprice);
                if ( strcmp("BTC",Q.destcoin) == 0 || strcmp("BTC",Q.srccoin) == 0 )
                    Q.satoshis *= 0.999;
                else Q.satoshis *= 0.9999;
            } else break;
        }
        if ( i == maxiters || qprice > maxprice )
        {
            printf("i.%d maxiters.%d qprice %.8f vs maxprice %.8f, no acceptable quote for this pubkey\n",i,maxiters,dstr(qprice),dstr(maxprice));
            if ( bits256_nonz(destpubkey) == 0 )
                continue;
            else return(clonestr("{\"error\":\"cant ordermatch to destpubkey\"}"));
        }
        printf("i.%d maxiters.%d qprice %.8f vs maxprice %.8f\n",i,maxiters,dstr(qprice),dstr(maxprice));
        return(LP_trade(ctx,myipaddr,mypubsock,&Q,maxprice,timeout,duration,tradeid,destpubkey));
    }
    return(clonestr("{\"error\":\"cant get here\"}"));
#endif
}


