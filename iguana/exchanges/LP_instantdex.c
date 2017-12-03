
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
//  LP_instantdex.c
//  marketmaker
//

void LP_instantdex_txidaddfname(char *fname,char *afname)
{
    sprintf(fname,"%s/instantdex.json",GLOBAL_DBDIR);
    sprintf(afname,"%s/instantdex_append.json",GLOBAL_DBDIR);
}

cJSON *LP_instantdex_txids()
{
    char *filestr,fname[1024],afname[1024]; long fsize; cJSON *retjson=0;
    LP_instantdex_txidaddfname(fname,afname);
    if ( (filestr= OS_filestr(&fsize,fname)) != 0 )
    {
        retjson = cJSON_Parse(filestr);
        free(filestr);
    } else printf("couldnt open (%s)\n",fname);
    return(retjson);
}

void LP_instantdex_filewrite(int32_t appendfile,cJSON *array)
{
    FILE *fp; char *filestr,fname[1024],afname[1024];
    LP_instantdex_txidaddfname(fname,afname);
    if ( (fp= fopen(appendfile == 0 ? fname : afname,"wb")) != 0 )
    {
        filestr = jprint(array,0);
        fwrite(filestr,1,strlen(filestr)+1,fp);
        fclose(fp);
        free(filestr);
    }
}

void LP_instantdex_txidadd(bits256 txid)
{
    cJSON *array; int32_t i,n;
    if ( (array= LP_instantdex_txids()) == 0 )
        array = cJSON_CreateArray();
    if ( (n= cJSON_GetArraySize(array)) >= 0 )
    {
        for (i=0; i<n; i++)
            if ( bits256_cmp(jbits256i(array,i),txid) == 0 )
                break;
        if ( i == n )
        {
            jaddibits256(array,txid);
            LP_instantdex_filewrite(0,array);
            LP_instantdex_filewrite(1,array);
        }
    }
    if ( array != 0 )
        free_json(array);
}

int32_t LP_deposit_addr(char *p2shaddr,uint8_t *script,uint8_t taddr,uint8_t p2shtype,uint32_t timestamp,uint8_t *pubsecp33)
{
    uint8_t elsepub33[33],p2sh_rmd160[20]; int32_t n;
    decode_hex(elsepub33,33,BOTS_BONDPUBKEY33);
    n = bitcoin_performancebond(p2sh_rmd160,script,0,timestamp,pubsecp33,elsepub33);
    bitcoin_address(p2shaddr,taddr,p2shtype,script,n);
    return(n);
}

char *LP_instantdex_deposit(struct iguana_info *coin,int32_t weeks,double amount,int32_t broadcast)
{
    char p2shaddr[64],*retstr,*hexstr; uint8_t script[512]; int32_t weeki,scriptlen; cJSON *argjson,*retjson,*array,*item,*obj; uint32_t timestamp; bits256 txid,sendtxid; uint64_t amount64;
    if ( strcmp(coin->symbol,"KMD") != 0 )
        return(clonestr("{\"error\":\"instantdex deposit must be in KMD\"}"));
    if ( amount < 10.0 )
        return(clonestr("{\"error\":\"minimum instantdex deposit is 10 KMD\"}"));
    if ( weeks <= 0 || weeks > 52 )
        return(clonestr("{\"error\":\"weeks must be between 1 and 52\"}"));
    if ( weeks > 0 )
    {
        timestamp = (uint32_t)time(NULL);
        timestamp /= LP_WEEKMULT;
        timestamp += weeks+1;
        timestamp *= LP_WEEKMULT;
        weeki = (timestamp - LP_FIRSTWEEKTIME) / LP_WEEKMULT;
        if ( weeks >= 10000 )
            return(clonestr("{\"error\":\"numweeks must be less than 10000\"}"));
    } else timestamp = (uint32_t)time(NULL) + 300, weeki = 0;
    scriptlen = LP_deposit_addr(p2shaddr,script,coin->taddr,coin->p2shtype,timestamp,G.LP_pubsecp);
    argjson = cJSON_CreateObject();
    array = cJSON_CreateArray();
    item = cJSON_CreateObject();
    jaddnum(item,p2shaddr,amount);
    jaddi(array,item);
    item = cJSON_CreateObject();
    amount64 = (amount * SATOSHIDEN) / 1000;
    amount64 = (amount64 / 10000) * 10000 + weeki;
    jaddnum(item,BOTS_BONDADDRESS,dstr(amount64));
    jaddi(array,item);
    item = cJSON_CreateObject();
    jaddnum(item,coin->smartaddr,0.0001);
    jaddi(array,item);
    jadd(argjson,"outputs",array);
    //printf("deposit.(%s)\n",jprint(argjson,0));
    if ( (retstr= LP_withdraw(coin,argjson)) != 0 )
    {
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( jobj(retjson,"result") != 0 )
                jdelete(retjson,"result");
            jaddstr(retjson,"address",p2shaddr);
            jaddnum(retjson,"expiration",timestamp);
            jaddnum(retjson,"deposit",amount);
            if ( (obj= jobj(retjson,"complete")) != 0 && is_cJSON_True(obj) != 0 && (hexstr= jstr(retjson,"hex")) != 0 )
            {
                txid = jbits256(retjson,"txid");
                if ( bits256_nonz(txid) != 0 )
                    LP_instantdex_txidadd(txid);
                if ( broadcast != 0 )
                {
                    if (bits256_nonz(txid) != 0 )
                    {
                        sendtxid = LP_broadcast("deposit","KMD",hexstr,txid);
                        if ( bits256_cmp(sendtxid,txid) != 0 )
                        {
                            jaddstr(retjson,"error","broadcast txid mismatch");
                            jaddbits256(retjson,"broadcast",sendtxid);
                            free(retstr);
                            return(jprint(retjson,1));
                        }
                        else
                        {
                            jaddstr(retjson,"result","success");
                            jaddbits256(retjson,"broadcast",sendtxid);
                            free(retstr);
                            return(jprint(retjson,1));
                        }
                    }
                    else
                    {
                        jaddstr(retjson,"error","couldnt broadcast since no txid created");
                        free(retstr);
                        return(jprint(retjson,1));
                    }
                }
                else
                {
                    jaddstr(retjson,"result","success");
                    free(retstr);
                    return(jprint(retjson,1));
                }
            }
            else
            {
                jaddstr(retjson,"error","couldnt create deposit txid");
                free(retstr);
                return(jprint(retjson,1));
            }
            free_json(retjson);
        }
        free(retstr);
    }
    return(clonestr("{\"error\":\"error with LP_withdraw for instantdex deposit\"}"));
}

int64_t LP_claimtx(void *ctx,struct iguana_info *coin,bits256 *claimtxidp,bits256 utxotxid,int32_t utxovout,uint64_t satoshis,char *vinaddr,uint32_t claimtime,uint8_t *redeemscript,int32_t redeemlen)
{
    uint8_t userdata[2];  char *signedtx; bits256 signedtxid,sendtxid; int32_t isbots,userdatalen; int64_t destamount,sum = 0;
    if ( strcmp(coin->smartaddr,BOTS_BONDADDRESS) == 0 )
        isbots = 1;
    else isbots = 0;
    userdata[0] = (isbots == 0) ? 0x51 : 0;
    userdatalen = 1;
    utxovout = 0;
    memset(claimtxidp,0,sizeof(*claimtxidp));
    char str[65]; printf("satoshis %.8f %s/v%d\n",dstr(satoshis),bits256_str(str,utxotxid),utxovout);
    if ( (signedtx= basilisk_swap_bobtxspend(&signedtxid,10000,"instantdexclaim",coin->symbol,coin->wiftaddr,coin->taddr,coin->pubtype,coin->p2shtype,coin->isPoS,coin->wiftype,ctx,G.LP_privkey,0,redeemscript,redeemlen,userdata,userdatalen,utxotxid,utxovout,coin->smartaddr,G.LP_pubsecp,0,claimtime,&destamount,0,0,vinaddr,1,coin->zcash)) != 0 )
    {
        printf("signedtx.(%s)\n",signedtx);
        sendtxid = LP_broadcast("claim","KMD",signedtx,signedtxid);
        if ( bits256_cmp(sendtxid,signedtxid) == 0 )
        {
            *claimtxidp = sendtxid;
            sum += (satoshis - coin->txfee);
        }
        else printf("error sending %s\n",bits256_str(str,signedtxid));
        free(signedtx);
    } else printf("error claiming instantdex deposit %s/v%d %.8f\n",bits256_str(str,utxotxid),utxovout,dstr(satoshis));
    return(sum);
}

int32_t LP_claim_submit(void *ctx,cJSON *txids,int64_t *sump,struct iguana_info *coin,bits256 utxotxid)
{
    uint8_t redeemscript[512]; bits256 claimtxid; cJSON *txjson,*vout0,*vout1,*vout2,*vouts,*item; int32_t numvouts; char str[65],vinaddr[64],destaddr[64],checkaddr[64]; int32_t j,utxovout,flagi = 0,redeemlen,weeki; int64_t weeksatoshis,satoshis; uint32_t expiration,claimtime;
    if ( (txjson= LP_gettx(coin->symbol,utxotxid,1)) != 0 )
    {
        if ( (vouts= jarray(&numvouts,txjson,"vout")) != 0 && numvouts >= 3 )
        {
            vout0 = jitem(vouts,0);
            LP_destaddr(vinaddr,vout0);
            satoshis = LP_value_extract(vout0,1);
            vout2 = jitem(vouts,2);
            LP_destaddr(destaddr,vout2);
            if ( strcmp(destaddr,coin->smartaddr) == 0 )
            {
                vout1 = jitem(vouts,1);
                weeksatoshis = LP_value_extract(vout1,0);
                weeki = (int32_t)(weeksatoshis % 10000);
                for (j=0; j<2*168; j++)
                {
                    if ( j >= 168 )
                        expiration = ((weeki * LP_WEEKMULTBAD + (j-168)*3600) + LP_FIRSTWEEKTIME);
                    else expiration = ((weeki * LP_WEEKMULT + j*3600) + LP_FIRSTWEEKTIME);
                    redeemlen = LP_deposit_addr(checkaddr,redeemscript,coin->taddr,coin->p2shtype,expiration,G.LP_pubsecp);
                    if ( strcmp(checkaddr,vinaddr) == 0 )
                    {
                        flagi = 1;
                        claimtime = (uint32_t)time(NULL)-777;
                        item = cJSON_CreateObject();
                        jaddbits256(item,"txid",utxotxid);
                        jaddnum(item,"deposit",dstr(LP_value_extract(vout0,0)));
                        if ( coin->electrum == 0 )
                            jaddnum(item,"interest",dstr(satoshis)-dstr(LP_value_extract(vout0,0)));
                        else jaddnum(item,"interest",dstr(LP_komodo_interest(utxotxid,satoshis)));
                        if ( claimtime <= expiration )
                        {
                            printf("claimtime.%u vs %u, wait %d seconds to %s claim %.8f\n",claimtime,expiration,(int32_t)expiration-claimtime,bits256_str(str,utxotxid),dstr(satoshis));
                            jaddnum(item,"waittime",(int32_t)expiration-claimtime);
                            jaddi(txids,item);
                            break;
                        }
                        else
                        {
                            utxovout = 0;
                            *sump += LP_claimtx(ctx,coin,&claimtxid,utxotxid,utxovout,satoshis,vinaddr,claimtime,redeemscript,redeemlen);
                            if ( bits256_nonz(claimtxid) != 0 )
                            {
                                jaddbits256(item,"claimtxid",claimtxid);
                                jaddi(txids,item);
                            }
                        }
                    } //else printf("expiration.%u j.%d checkaddr.(%s) != vinaddr.%s\n",expiration,j,checkaddr,vinaddr);
                    if ( flagi != 0 )
                        break;
                }
            } else printf("vout2 dest.(%s) != %s\n",destaddr,coin->smartaddr);
        } else printf("numvouts %d != 3\n",numvouts);
        free_json(txjson);
    } else printf("cant get transaction\n");
    return(flagi);
}

char *LP_instantdex_claim(struct iguana_info *coin)
{
    static void *ctx;
    int32_t i,n; cJSON *array,*txids,*newarray,*retjson; int64_t sum; bits256 utxotxid;
    if ( ctx == 0 )
        ctx = bitcoin_ctx();
    if ( strcmp(coin->symbol,"KMD") != 0 )
        return(clonestr("{\"error\":\"instantdex deposit must be in KMD\"}"));
    sum = 0;
    txids = cJSON_CreateArray();
    newarray = cJSON_CreateArray();
    if ( (array= LP_instantdex_txids()) != 0 )
    {
        printf("claiming from.(%s)\n",jprint(array,0));
        if ( (n= cJSON_GetArraySize(array)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                utxotxid = jbits256i(array,i);
                if ( LP_claim_submit(ctx,txids,&sum,coin,utxotxid) == 0 )
                    jaddibits256(newarray,utxotxid);
            }
        }
        free_json(array);
    }
    if ( cJSON_GetArraySize(newarray) > 0 )
        LP_instantdex_filewrite(0,newarray);
    free_json(newarray);
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"result","success");
    jaddnum(retjson,"claimed",dstr(sum));
    jadd(retjson,"txids",txids);
    return(jprint(retjson,1));
}

int64_t LP_instantdex_credit(int32_t dispflag,char *coinaddr,int64_t satoshis,int32_t weeki,char *p2shaddr,bits256 txid)
{
    uint32_t timestamp; struct LP_address *ap; struct iguana_info *coin = LP_coinfind("KMD");
    if ( coin != 0 )
    {
        timestamp = LP_FIRSTWEEKTIME + weeki*LP_WEEKMULT;
        if ( (ap= LP_address(coin,coinaddr)) != 0 && time(NULL) < timestamp-60*3600 )
        {
            ap->instantdex_credits += satoshis;
            ap->didinstantdex = 1;
            if ( strcmp(coinaddr,coin->smartaddr) == 0 )
                LP_instantdex_txidadd(txid);
            if ( dispflag != 0 )
                printf("InstantDEX credit.(%s) %.8f weeki.%d (%s) -> sum %.8f\n",coinaddr,dstr(satoshis),weeki,p2shaddr,dstr(ap->instantdex_credits));
            return(satoshis);
        } //else printf("null ap.%p or expired %ld\n",ap,time(NULL) - (timestamp-60*3600));
    }
    return(0);
}

int64_t LP_instantdex_creditcalc(struct iguana_info *coin,int32_t dispflag,bits256 txid,char *refaddr)
{
    cJSON *txjson,*vouts,*txobj,*item; int64_t satoshis=0,amount64; int32_t weeki,numvouts; char destaddr[64],p2shaddr[64];
    if ( (txjson= LP_gettx(coin->symbol,txid,0)) != 0 )
    {
        // vout0 deposit, vout1 botsfee, vout2 smartaddress
        if ( (vouts= jarray(&numvouts,txjson,"vout")) > 0 && numvouts >= 3 && LP_destaddr(destaddr,jitem(vouts,2)) == 0 )
        {
            if ( refaddr != 0 && strcmp(refaddr,destaddr) != 0 )
            {
                printf("LP_instantdex_creditcalc for (%s) but deposit sent for (%s)\n",refaddr,destaddr);
            }
            else
            {
                amount64 = LP_value_extract(jitem(vouts,1),0);
                weeki = (amount64 % 10000);
                item = jitem(vouts,0);
                satoshis = LP_value_extract(item,0);
                //printf("%s %s funded %.8f weeki.%d (%s)\n",bits256_str(str,txid),destaddr,dstr(satoshis),weeki,jprint(item,0));
                if ( LP_destaddr(p2shaddr,item) == 0 )
                {
                    if ( (txobj= LP_gettxout(coin->symbol,p2shaddr,txid,0)) != 0 )
                    {
                        free_json(txobj);
                        LP_instantdex_credit(dispflag,destaddr,satoshis,weeki,p2shaddr,txid);
                    } else printf("already spent\n");
                } else printf("error getting p2shaddr.(%s)\n",p2shaddr);
            }
        }
        free_json(txjson);
    }
    return(satoshis);
}

#ifdef bruteforce
void LP_instantdex_deposits(struct iguana_info *coin)
{
    static int dispflag = 1;
    cJSON *array,*item; int32_t i,n,height,vout; bits256 txid; struct LP_address *ap,*tmp;
    if ( coin->electrum != 0 )//&& coin->electruminstantdex != 0 )
        return;
    HASH_ITER(hh,coin->addresses,ap,tmp)
    {
        ap->instantdex_credits = 0;
    }
    if ( (array= LP_listreceivedbyaddress("KMD",BOTS_BONDADDRESS)) != 0 )
    {
        //printf("instantdex.(%s)\n",jprint(array,0));
        if ( (n= cJSON_GetArraySize(array)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                if ( coin->electrum != 0 )
                {
                    item = jitem(array,i);
                    LP_listunspent_parseitem(coin,&txid,&vout,&height,item);
                } else txid = jbits256i(array,i);
                LP_instantdex_creditcalc(coin,dispflag,txid,0);
            }
        }
        free_json(array);
    }
    dispflag = 0;
}
#endif

int64_t LP_dynamictrust(bits256 pubkey,int64_t kmdvalue)
{
    struct LP_pubswap *ptr,*tmp; struct LP_swapstats *sp; struct LP_pubkey_info *pubp; struct LP_address *ap; char coinaddr[64]; struct iguana_info *coin; int64_t swaps_kmdvalue = 0;
    if ( (coin= LP_coinfind("KMD")) != 0 && (pubp= LP_pubkeyfind(pubkey)) != 0 )
    {
        bitcoin_address(coinaddr,coin->taddr,coin->pubtype,pubp->pubsecp,33);
        if ((ap= LP_address(coin,coinaddr)) != 0 )//&& ap->instantdex_credits >= kmdvalue )
        {
            DL_FOREACH_SAFE(pubp->bobswaps,ptr,tmp)
            {
                if ( (sp= ptr->swap) != 0 && LP_swap_finished(sp,1) == 0 )
                    swaps_kmdvalue += LP_kmdvalue(sp->Q.srccoin,sp->Q.satoshis);
            }
            DL_FOREACH_SAFE(pubp->aliceswaps,ptr,tmp)
            {
                if ( (sp= ptr->swap) != 0 && LP_swap_finished(sp,1) == 0 )
                    swaps_kmdvalue += LP_kmdvalue(sp->Q.destcoin,sp->Q.destsatoshis);
            }
            if ( ap->instantdex_credits != 0 && (swaps_kmdvalue+kmdvalue) > ap->instantdex_credits )
            printf("%s instantdex_credits %.8f vs (%.8f + current %.8f)\n",coinaddr,dstr(ap->instantdex_credits),dstr(swaps_kmdvalue),dstr(kmdvalue));
            //if ( ap->instantdex_credits > swaps_kmdvalue+kmdvalue )
                return(ap->instantdex_credits - (swaps_kmdvalue+kmdvalue));
        }
    }
    return(0);
}

int64_t LP_instantdex_proofcheck(char *coinaddr,cJSON *proof,int32_t num)
{
    uint8_t rmd160[20],addrtype; int32_t i; int64_t net = 0; char othersmartaddr[64]; struct iguana_info *coin; struct LP_address *ap = 0;
    if ( (coin= LP_coinfind("KMD")) != 0 )
    {
        bitcoin_addr2rmd160(0,&addrtype,rmd160,coinaddr);
        bitcoin_address(othersmartaddr,0,60,rmd160,20);
        if ((ap= LP_address(coin,othersmartaddr)) != 0 )//&& (coin->electrum == 0 || ap->didinstantdex == 0) )
        {
            ap->instantdex_credits = 0;
            for (i=0; i<num; i++)
                LP_instantdex_creditcalc(coin,1,jbits256i(proof,i),othersmartaddr);
            ap->didinstantdex = 1;
            //if ( ap->instantdex_credits > 0 )
            printf("validated instantdex %s.[%d] proof.(%s) credits %.8f net %.8f\n",othersmartaddr,num,jprint(proof,0),dstr(ap->instantdex_credits),dstr(net));
        } //else printf("cant find ap.%p or already did %d %.8f\n",ap,ap!=0?ap->didinstantdex:-1,ap!=0?dstr(ap->instantdex_credits):-1);
    }
    return(ap->instantdex_credits);
}

int64_t LP_myzcredits()
{
    cJSON *proof; struct iguana_info *coin; int64_t zcredits;
    if ( (coin= LP_coinfind("KMD")) != 0 )
    {
        if ( (proof= LP_instantdex_txids()) != 0 )
        {
            zcredits = LP_instantdex_proofcheck(coin->smartaddr,proof,cJSON_GetArraySize(proof));
            free_json(proof);
            return(zcredits);
        }
    }
    return(0);
}

cJSON *LP_swapstats_item(struct LP_swapstats *sp,int32_t iambob)
{
    struct iguana_info *bob,*alice; int32_t flag = 0; char *retstr,*swapstr; bits256 zero; cJSON *item,*reqjson,*swapjson;
    item = cJSON_CreateObject();
    jaddnum(item,"iambob",iambob);
    jaddnum(item,"aliceid",sp->aliceid);
    jaddnum(item,"requestid",sp->Q.R.requestid);
    jaddnum(item,"quoteid",sp->Q.R.quoteid);
    jaddstr(item,"base",sp->Q.srccoin);
    jaddnum(item,"satoshis",sp->Q.satoshis);
    jaddstr(item,"rel",sp->Q.destcoin);
    jaddnum(item,"destsatoshis",sp->Q.destsatoshis);
    jaddnum(item,"price",sp->Q.destsatoshis/((double)sp->Q.satoshis+1));
    if ( LP_swap_finished(sp,1) == 0 )
    {
        jaddnum(item,"finished",sp->finished);
        if ( sp->bobneeds_dPoW != 0 && (bob= LP_coinfind(sp->Q.srccoin)) != 0 )
        {
            jaddnum(item,"bobneeds_dPoW",sp->bobneeds_dPoW);
            jaddnum(item,"bob_dPoWheight",bob->notarized);
            if ( sp->bobneeds_dPoW == 1 )
                flag = 1;
            if ( bob->notarized == 0 )
                LP_dPoW_request(bob);
        }
        if ( sp->aliceneeds_dPoW != 0 && (alice= LP_coinfind(sp->Q.destcoin)) != 0 )
        {
            jaddnum(item,"aliceneeds_dPoW",sp->aliceneeds_dPoW);
            jaddnum(item,"alice_dPoWheight",alice->notarized);
            if ( sp->aliceneeds_dPoW == 1 )
                flag = 1;
            if ( alice->notarized == 0 )
                LP_dPoW_request(alice);
        }
        if ( flag != 0 )
        {
            reqjson = cJSON_CreateObject();
            jaddstr(reqjson,"method","gettradestatus");
            jadd64bits(reqjson,"aliceid",sp->aliceid);
            memset(zero.bytes,0,sizeof(zero));
            LP_reserved_msg(0,"","",zero,jprint(reqjson,1));
            if ( (swapstr= basilisk_swapentry(sp->Q.R.requestid,sp->Q.R.quoteid,0)) != 0 )
            {
                if ( (swapjson= cJSON_Parse(swapstr)) != 0 )
                {
                    if ( (retstr= LP_swapstatus_recv(swapjson)) != 0 )
                        free(retstr);
                    free_json(swapjson);
                }
                free(swapstr);
            }
        }
    }
    return(item);
}

cJSON *LP_myzdebits()
{
    struct LP_pubswap *ptr,*tmp; struct LP_pubkey_info *pubp; struct LP_swapstats *sp; int64_t kmdvalue,swaps_kmdvalue = 0; struct iguana_info *coin; cJSON *retjson,*array,*item;
    array = cJSON_CreateArray();
    if ( (coin= LP_coinfind("KMD")) != 0 )
    {
        if ( (pubp= LP_pubkeyfind(G.LP_mypub25519)) != 0 )
        {
            DL_FOREACH_SAFE(pubp->bobswaps,ptr,tmp)
            {
                if ( (sp= ptr->swap) != 0 && LP_swap_finished(sp,1) == 0 )
                {
                    kmdvalue = LP_kmdvalue(sp->Q.srccoin,sp->Q.satoshis);
                    item = LP_swapstats_item(sp,1);
                    jaddnum(item,"kmdvalue",dstr(kmdvalue));
                    jaddi(array,item);
                    swaps_kmdvalue += kmdvalue;
                }
            }
            DL_FOREACH_SAFE(pubp->aliceswaps,ptr,tmp)
            {
                if ( (sp= ptr->swap) != 0 && LP_swap_finished(sp,1) == 0 )
                {
                    kmdvalue = LP_kmdvalue(sp->Q.destcoin,sp->Q.destsatoshis);
                    item = LP_swapstats_item(sp,0);
                    jaddnum(item,"kmdvalue",dstr(kmdvalue));
                    jaddi(array,item);
                    swaps_kmdvalue += kmdvalue;
                }
            }
        }
    }
    retjson = cJSON_CreateObject();
    jadd(retjson,"swaps",array);
    jaddnum(retjson,"pendingswaps",dstr(swaps_kmdvalue));
    return(retjson);
}
