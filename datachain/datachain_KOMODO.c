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

// included from datachain.c

int32_t datachain_rwgenesis(int32_t rwflag,uint8_t *serialized,struct gecko_genesis_opreturn *opret)
{
    int32_t len = 0;
    if ( rwflag == 0 )
    {
        memcpy(opret->type,&serialized[len],sizeof(opret->type)), len += sizeof(opret->type);
        memcpy(opret->symbol,&serialized[len],sizeof(opret->symbol)), len += sizeof(opret->symbol);
        memcpy(opret->name,&serialized[len],sizeof(opret->name)), len += sizeof(opret->name);
    }
    else
    {
        memcpy(&serialized[len],opret->type,sizeof(opret->type)), len += sizeof(opret->type);
        memcpy(&serialized[len],opret->symbol,sizeof(opret->symbol)), len += sizeof(opret->symbol);
        memcpy(&serialized[len],opret->name,sizeof(opret->name)), len += sizeof(opret->name);
    }
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(opret->PoSvalue),&opret->PoSvalue);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(opret->netmagic),&opret->netmagic);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(opret->timestamp),&opret->timestamp);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(opret->nBits),&opret->nBits);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(opret->nonce),&opret->nonce);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(opret->blocktime),&opret->blocktime);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(opret->port),&opret->port);
    if ( rwflag == 0 )
    {
        opret->version = serialized[len++];
        opret->pubval = serialized[len++];
        opret->p2shval = serialized[len++];
        opret->wifval = serialized[len++];
        memcpy(opret->rmd160,&serialized[len],20), len += 20;
    }
    else
    {
        serialized[len++] = opret->version;
        serialized[len++] = opret->pubval;
        serialized[len++] = opret->p2shval;
        serialized[len++] = opret->wifval;
        memcpy(&serialized[len],opret->rmd160,20), len += 20;
    }
    //printf("opreturn len.%d\n",len);
    return(len);
}

bits256 datachain_opreturn_convert(uint8_t *txidbytes,int32_t *txlenp,struct iguana_msgblock *msg,struct gecko_genesis_opreturn *opret)
{
    bits256 txid,zero; int32_t minerpaymentlen=0; uint8_t minerpayment[512]; char coinbasestr[128],name[64],symbol[64];
    if ( opret->PoSvalue > 0 )
        minerpaymentlen = bitcoin_standardspend(minerpayment,0,opret->rmd160);
    memset(zero.bytes,0,sizeof(zero));
    memset(symbol,0,sizeof(symbol)), memcpy(symbol,opret->symbol,sizeof(opret->symbol));
    memset(name,0,sizeof(name)), memcpy(name,opret->name,sizeof(opret->name));
    sprintf(coinbasestr,"%s_%s",symbol,name);
    *txlenp = iguana_coinbase(1,GECKO_DEFAULTVERSION,txidbytes,opret->timestamp,zero,(uint8_t *)coinbasestr,(int32_t)strlen(coinbasestr)+1,minerpayment,minerpaymentlen,opret->PoSvalue,&txid);
    memset(msg,0,sizeof(*msg));
    msg->H.version = opret->version;
    msg->H.merkle_root = txid;
    msg->H.timestamp = opret->timestamp;
    msg->H.bits = opret->nBits;
    msg->H.nonce = opret->nonce;
    return(txid);
}

int32_t datachain_genesis_verify(struct gecko_genesis_opreturn *opret)
{
    int32_t txlen,datalen; bits256 txid,threshold,hash2; uint8_t serialized[1024],txidbytes[1024]; struct iguana_msgblock msg; char str[65],str2[65];
    txid = datachain_opreturn_convert(txidbytes,&txlen,&msg,opret);
    if ( opret->nBits >= GECKO_EASIESTDIFF )
        threshold = bits256_from_compact(GECKO_EASIESTDIFF);
    else threshold = bits256_from_compact(opret->nBits);
    datalen = iguana_rwblockhdr(1,0,serialized,&msg);
    hash2 = iguana_calcblockhash("virtual",blockhash_sha256,serialized,datalen);
    //for (i=0; i<datalen; i++)
    //    printf("%02x",serialized[i]);
    if ( bits256_cmp(threshold,hash2) > 0 )
    {
        //printf(" valid blockhash!\n");
        return(0);
    }
    else
    {
        printf(" ERROR invalid blockhash! txid.%s %s\n",bits256_str(str2,txid),bits256_str(str,hash2));
        return(-1);
    }
}

int32_t datachain_opreturn_create(uint8_t *serialized,char *symbol,char *name,char *coinaddr,int64_t PoSvalue,uint32_t nBits,uint16_t blocktime,uint16_t port,uint8_t p2shval,uint8_t wifval)
{
    int32_t i,len,datalen,txlen; struct gecko_genesis_opreturn opret; bits256 threshold,txid,hash2; struct iguana_info *btcd; struct iguana_msgblock msg; uint8_t txidbytes[1024];
    btcd = iguana_coinfind("BTCD");
    memset(&opret,0,sizeof(opret));
    opret.type[0] = 'N', opret.type[1] = 'E', opret.type[2] = 'W';
    memcpy(opret.symbol,symbol,sizeof(opret.symbol));
    memcpy(opret.name,name,sizeof(opret.name));
    opret.version = GECKO_DEFAULTVERSION;
    opret.PoSvalue = PoSvalue;
    opret.nBits = nBits;
    opret.p2shval = p2shval;
    opret.wifval = wifval;
    opret.blocktime = blocktime;
    opret.port = port;
    opret.timestamp = (uint32_t)time(NULL);
    OS_randombytes((void *)&opret.netmagic,sizeof(opret.netmagic));
    bitcoin_addr2rmd160(&opret.pubval,opret.rmd160,coinaddr);
    txid = datachain_opreturn_convert(txidbytes,&txlen,&msg,&opret);
    if ( nBits >= GECKO_EASIESTDIFF )
        threshold = bits256_from_compact(GECKO_EASIESTDIFF);
    else threshold = bits256_from_compact(nBits);
    for (i=0; i<100000000; i++)
    {
        opret.nonce = msg.H.nonce = i;
        datalen = iguana_rwblockhdr(1,0,serialized,&msg);
        hash2 = iguana_calcblockhash(symbol,btcd->chain->hashalgo,serialized,datalen);
        if ( bits256_cmp(threshold,hash2) > 0 )
            break;
    }
    //char str[65],str2[65];
    //for (i=0; i<datalen; i++)
    //    printf("%02x",serialized[i]);
    //printf(" <- msgblock datalen.%d txid.%s hash2.%s\n",datalen,bits256_str(str,txid),bits256_str(str2,hash2));
    len = datachain_rwgenesis(1,serialized,&opret);
    datachain_genesis_verify(&opret);
    return(len);
}

void datachain_events_processKOMODO(struct supernet_info *myinfo,struct datachain_info *dPoW,struct datachain_event *event)
{
    struct gecko_chain *chain; bits256 hash2,threshold; struct gecko_genesis_opreturn opret; int32_t datalen,i,j,len,txlen; char symbol[16],name[64],magicstr[16],blockstr[8192],nbitstr[16],issuer[64],hashstr[65],str2[65],argbuf[1024],chainname[GECKO_MAXNAMELEN]; cJSON *valsobj; struct iguana_msgblock msg; uint8_t serialized[256],txidbytes[1024],buf[4]; struct iguana_info *virt,*btcd;
    if ( (btcd= iguana_coinfind("BTCD")) != 0 && memcmp(event->opreturn,"NEW",3) == 0 )
    {
        //int32_t i; for (i=0; i<76; i++)
        //    printf("%02x",event->opreturn[i]);
        //printf(" <- event\n");
        if ( (len= datachain_rwgenesis(0,event->opreturn,&opret)) <= event->oplen )
        {
            datachain_genesis_verify(&opret);
            memset(symbol,0,sizeof(symbol)), memcpy(symbol,opret.symbol,sizeof(opret.symbol));
            memset(name,0,sizeof(name)), memcpy(name,opret.name,sizeof(opret.name));
            hash2 = datachain_opreturn_convert(txidbytes,&txlen,&msg,&opret);
            if ( opret.nBits >= GECKO_EASIESTDIFF )
                threshold = bits256_from_compact(GECKO_EASIESTDIFF);
            else threshold = bits256_from_compact(opret.nBits);
            msg.txn_count = 1;
            //n = iguana_serialize_block(virt->chain,&hash2,serialized,newblock);
            datalen = iguana_rwblockhdr(1,0,serialized,&msg);
            hash2 = iguana_calcblockhash(symbol,btcd->chain->hashalgo,serialized,datalen);
            for (i=0; i<datalen; i++)
                printf("%02x",serialized[i]);
            printf(" <- genhdr.%d\n",datalen);
            for (i=0; i<txlen; i++)
                printf("%02x",txidbytes[i]);
            printf(" <- genesistx\n");
            //char str[65]; printf("komodo datalen.%d %s\n",datalen,bits256_str(str,hash2));
            if ( bits256_cmp(threshold,hash2) > 0 )
            {
                bitcoin_address(issuer,60,opret.rmd160,20);
                bits256_str(hashstr,hash2);
                for (j=0,i=3; i>=0; i--,j++)
                    buf[i] = (opret.netmagic >> (j*8));
                init_hexbytes_noT(magicstr,buf,4);
                for (j=0,i=3; i>=0; i--,j++)
                    buf[i] = (opret.nBits >> (j*8));
                init_hexbytes_noT(nbitstr,buf,4);
                init_hexbytes_noT(blockstr,serialized,datalen);
                strcat(blockstr,"01"), datalen++;
                init_hexbytes_noT(&blockstr[datalen << 1],txidbytes,txlen);
                sprintf(argbuf,"{\"name\":\"%s\",\"symbol\":\"%s\",\"netmagic\":\"%s\",\"port\":%u,\"blocktime\":%u,\"pubval\":\"%02x\",\"p2shval\":\"%02x\",\"wifval\":\"%02x\",\"unitval\":\"%02x\",\"genesishash\":\"%s\",\"genesis\":{\"version\":1,\"timestamp\":%u,\"nBits\":\"%s\",\"nonce\":%d,\"merkle_root\":\"%s\"},\"genesisblock\":\"%s\"}",name,symbol,magicstr,opret.port,opret.blocktime,opret.pubval,opret.p2shval,opret.wifval,(opret.nBits >> 24) & 0xff,hashstr,opret.timestamp,nbitstr,opret.nonce,bits256_str(str2,msg.H.merkle_root),blockstr);
                if ( (valsobj= cJSON_Parse(argbuf)) != 0 )
                {
                    printf("datachain.NEW (%s/%s port.%u blocktime.%d) issuer.%s (%s)\n",opret.symbol,opret.name,opret.port,opret.blocktime,issuer,jprint(valsobj,0));
                    if ( (chain= gecko_chain(myinfo,chainname,valsobj)) != 0 && (virt= chain->info) != 0 )
                        printf("duplicate chain.%s rejected\n",opret.symbol);
                    else if ( (virt= basilisk_geckochain(myinfo,symbol,chainname,valsobj)) != 0 )
                        chain->info = virt;
                    free_json(valsobj);
                }
            } else printf("failed PoW test for genesis.%s\n",opret.symbol);
        } else printf("opret unexpected len.%d vs %d\n",len,event->oplen);
    }
}
