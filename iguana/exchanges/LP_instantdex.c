
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

void LP_instantdex_txidaddfname(char *fname)
{
    sprintf(fname,"%s/instantdex.json",GLOBAL_DBDIR);
}

cJSON *LP_instantdex_txidaddjson()
{
    char *filestr,fname[1024]; long fsize; cJSON *retjson=0;
    LP_instantdex_txidaddfname(fname);
    if ( (filestr= OS_filestr(&fsize,fname)) != 0 )
    {
        retjson = cJSON_Parse(filestr);
        free(filestr);
    }
    return(retjson);
}

void LP_instantdex_txidadd(bits256 txid)
{
    cJSON *array; int32_t i,n; char fname[1024],*filestr; FILE *fp;
    if ( (array= LP_instantdex_txidaddjson()) == 0 )
        array = cJSON_CreateArray();
    if ( (n= cJSON_GetArraySize(array)) >= 0 )
    {
        for (i=0; i<n; i++)
            if ( bits256_cmp(jbits256i(array,i),txid) == 0 )
                break;
        if ( i == n )
        {
            LP_instantdex_txidaddfname(fname);
            char str[65]; printf("add %s -> %s\n",bits256_str(str,txid),fname);
            jaddibits256(array,txid);
            if ( (fp= fopen(fname,"wb")) != 0 )
            {
                filestr = jprint(array,0);
                fwrite(filestr,1,strlen(filestr)+1,fp);
                fclose(fp);
                free(filestr);
            }
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
    if ( weeks < 0 || weeks > 52 )
        return(clonestr("{\"error\":\"weeks must be between 0 and 52\"}"));
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

char *LP_instantdex_claim(struct iguana_info *coin,char *depositaddr,uint32_t expiration)
{
    static void *ctx;
    uint8_t redeemscript[512],userdata[64]; char vinaddr[64],str[65],*signedtx=0; uint32_t timestamp,now,redeemlen,claimtime; int32_t i,n,height,utxovout,userdatalen; bits256 signedtxid,utxotxid,sendtxid,zero; int64_t sum,destamount,satoshis; cJSON *array,*item,*txids,*retjson;
    if ( ctx == 0 )
        ctx = bitcoin_ctx();
    if ( strcmp(coin->symbol,"KMD") != 0 )
        return(clonestr("{\"error\":\"instantdex deposit must be in KMD\"}"));
    now = (uint32_t)time(NULL);
    sum = 0;
    txids = cJSON_CreateArray();
    timestamp = (now / LP_WEEKMULT) * LP_WEEKMULT + LP_WEEKMULT;
    while ( timestamp > LP_FIRSTWEEKTIME )
    {
        if ( expiration != 0 )
            timestamp = expiration;
        else timestamp -= LP_WEEKMULT;
        redeemlen = LP_deposit_addr(vinaddr,redeemscript,coin->taddr,coin->p2shtype,timestamp,G.LP_pubsecp);
        if ( strcmp(depositaddr,vinaddr) == 0 )
        {
            claimtime = (uint32_t)time(NULL)-777;
            if ( claimtime <= timestamp )
            {
                printf("claimtime.%u vs locktime.%u, need to wait %d seconds\n",claimtime,timestamp,(int32_t)timestamp-claimtime);
            }
            else
            {
                printf("found %s at timestamp.%u\n",vinaddr,timestamp);
                memset(zero.bytes,0,sizeof(zero));
                if ( (array= LP_listunspent(coin->symbol,vinaddr,zero,zero)) != 0 )
                {
                    userdata[0] = 0x51;
                    userdatalen = 1;
                    utxovout = 0;
                    //printf("unspents.(%s)\n",jprint(array,0));
                    if ( (n= cJSON_GetArraySize(array)) > 0 )
                    {
                        for (i=0; i<n; i++)
                        {
                            item = jitem(array,i);
                            satoshis = LP_listunspent_parseitem(coin,&utxotxid,&utxovout,&height,item);
                            printf("satoshis %.8f %s/v%d\n",dstr(satoshis),bits256_str(str,utxotxid),utxovout);
                            if ( (signedtx= basilisk_swap_bobtxspend(&signedtxid,10000,"instantdexclaim",coin->symbol,coin->wiftaddr,coin->taddr,coin->pubtype,coin->p2shtype,coin->isPoS,coin->wiftype,ctx,G.LP_privkey,0,redeemscript,redeemlen,userdata,userdatalen,utxotxid,utxovout,coin->smartaddr,G.LP_pubsecp,0,claimtime,&destamount,0,0,vinaddr,1,coin->zcash)) != 0 )
                            {
                                printf("signedtx.(%s)\n",signedtx);
                                sendtxid = LP_broadcast("claim","KMD",signedtx,signedtxid);
                                if ( bits256_cmp(sendtxid,signedtxid) == 0 )
                                {
                                    jaddibits256(txids,sendtxid);
                                    sum += (satoshis-coin->txfee);
                                }
                                else printf("error sending %s\n",bits256_str(str,signedtxid));
                                free(signedtx);
                            } else printf("error claiming instantdex deposit %s/v%d %.8f\n",bits256_str(str,utxotxid),utxovout,dstr(satoshis));
                        }
                    }
                    free_json(array);
                    retjson = cJSON_CreateObject();
                    jaddstr(retjson,"result","success");
                    jaddnum(retjson,"claimed",dstr(sum));
                    jadd(retjson,"txids",txids);
                    return(jprint(retjson,1));
                }
            }
        }
        if ( expiration != 0 )
            break;
    }
    return(clonestr("{\"error\":\"no instantdex deposits to claim\"}"));
}

int64_t LP_instantdex_credit(int32_t dispflag,char *coinaddr,int64_t satoshis,int32_t weeki,char *p2shaddr,bits256 txid)
{
    uint32_t timestamp; struct LP_address *ap; struct iguana_info *coin = LP_coinfind("KMD");
    if ( coin != 0 )
    {
        timestamp = LP_FIRSTWEEKTIME + weeki*LP_WEEKMULT;
        if (  time(NULL) < timestamp-60*3600 && (ap= LP_address(coin,coinaddr)) != 0 )
        {
            ap->instantdex_credits += satoshis;
            ap->didinstantdex = 1;
            if ( strcmp(coinaddr,coin->smartaddr) == 0 )
                LP_instantdex_txidadd(txid);
            if ( dispflag != 0 )
                printf("InstantDEX credit.(%s) %.8f weeki.%d (%s) -> sum %.8f\n",coinaddr,dstr(satoshis),weeki,p2shaddr,dstr(ap->instantdex_credits));
            return(satoshis);
        }
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
                //printf("%s funded %.8f weeki.%d\n",destaddr,dstr(satoshis),weeki);
                if ( LP_destaddr(p2shaddr,item) == 0 )
                {
                    if ( (txobj= LP_gettxout(coin->symbol,p2shaddr,txid,0)) != 0 )
                    {
                        free_json(txobj);
                        LP_instantdex_credit(dispflag,destaddr,satoshis,weeki,p2shaddr,txid);
                    }
                }
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
                if ( (sp= ptr->swap) != 0 && sp->finished == 0 && sp->expired == 0 )
                    swaps_kmdvalue += LP_kmdvalue(sp->Q.srccoin,sp->Q.satoshis);
            }
            DL_FOREACH_SAFE(pubp->aliceswaps,ptr,tmp)
            {
                if ( (sp= ptr->swap) != 0 && sp->finished == 0 && sp->expired == 0 )
                    swaps_kmdvalue += LP_kmdvalue(sp->Q.destcoin,sp->Q.destsatoshis);
            }
            //printf("%s instantdex_credits %.8f vs (%.8f + current %.8f)\n",coinaddr,dstr(ap->instantdex_credits),dstr(swaps_kmdvalue),dstr(kmdvalue));
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
        if ((ap= LP_address(coin,othersmartaddr)) != 0 && (coin->electrum == 0 || ap->didinstantdex == 0) )
        {
            ap->instantdex_credits = 0;
            for (i=0; i<num; i++)
                LP_instantdex_creditcalc(coin,1,jbits256i(proof,i),othersmartaddr);
            ap->didinstantdex = 1;
            //if ( ap->instantdex_credits > 0 )
            printf("validated instantdex %s.[%d] proof.(%s) credits %.8f net %.8f\n",othersmartaddr,num,jprint(proof,0),dstr(ap->instantdex_credits),dstr(net));
        } else printf("cant find ap.%p or already did %d %.8f\n",ap,ap!=0?ap->didinstantdex:-1,ap!=0?dstr(ap->instantdex_credits):-1);
    }
    return(net);
}
