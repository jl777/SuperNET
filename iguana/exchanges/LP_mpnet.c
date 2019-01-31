
/******************************************************************************
 * Copyright © 2014-2018 The SuperNET Developers.                             *
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
//  LP_mpnet.c
//  marketmaker
//

bits256 MPNET_txids[1024];
int32_t num_MPNET_txids;

int32_t LP_quoteparse(struct LP_quoteinfo *qp,cJSON *argjson);
void LP_gtc_addorder(struct LP_quoteinfo *qp);
char *LP_withdraw(struct iguana_info *coin,cJSON *argjson);

int32_t LP_mpnet_find(bits256 txid)
{
    int32_t i;
    for (i=0; i<num_MPNET_txids; i++)
        if ( bits256_cmp(txid,MPNET_txids[i]) == 0 )
            return(i);
    return(-1);
}

int32_t LP_mpnet_add(bits256 txid)
{
    if ( num_MPNET_txids < sizeof(MPNET_txids)/sizeof(*MPNET_txids) )
    {
        MPNET_txids[num_MPNET_txids++] = txid;
        return(num_MPNET_txids);
    }
    printf("MPNET_txids[] overflow\n");
    return(-1);
}

int32_t LP_mpnet_remove(bits256 txid)
{
    int32_t i;
    if ( (i= LP_mpnet_find(txid)) >= 0 )
    {
        MPNET_txids[i] = MPNET_txids[--num_MPNET_txids];
        return(i);
    }
    return(-1);
}

int32_t LP_mpnet_addorder(struct LP_quoteinfo *qp)
{
    LP_gtc_addorder(qp);
    return(0);
}

void LP_mpnet_init() // problem is coins not enabled yet
{
    char fname[1024],line[8192]; FILE *fp; struct LP_quoteinfo Q; cJSON *argjson;
    sprintf(fname,"%s/GTC/orders",GLOBAL_DBDIR), OS_compatible_path(fname);
    if ( (fp= fopen(fname,"rb+")) != 0 )
    {
        while ( fgets(line,sizeof(line),fp) > 0 )
        {
            if ( (argjson= cJSON_Parse(line)) != 0 )
            {
                if ( LP_quoteparse(&Q,argjson) == 0 )
                {
                    if ( LP_mpnet_addorder(&Q) == 0 )
                        printf("GTC %s",line);
                }
                free_json(argjson);
            }
        }
        fclose(fp);
    }
}

void LP_mpnet_send(int32_t localcopy,char *msg,int32_t sendflag,char *otheraddr)
{
    char fname[1024]; int32_t len; FILE *fp; char *hexstr,*retstr; cJSON *argjson,*outputs,*item; struct iguana_info *coin; uint8_t linebuf[8192];
    if ( localcopy != 0 )
    {
        sprintf(fname,"%s/GTC/orders",GLOBAL_DBDIR), OS_compatible_path(fname);
        if ( (fp= fopen(fname,"rb+")) == 0 )
            fp = fopen(fname,"wb+");
        else fseek(fp,0,SEEK_END);
        fprintf(fp,"%s\n",msg);
        fclose(fp);
    }
    if ( G.mpnet != 0 && sendflag != 0 && (coin= LP_coinfind("CHIPS")) != 0 && coin->inactive == 0 )
    {
        // This code path is not usually active, so as a porting prop let's post a special notice when it is.
        printf("LP_mpnet_send] Doing something!\n");
        len = MMJSON_encode(linebuf,msg);
        //curl --url "http://127.0.0.1:7783" --data "{\"userpass\":\"$userpass\",\"method\":\"withdraw\",\"coin\":\"CHIPS\",\"outputs\":[{\"RHV2As4rox97BuE3LK96vMeNY8VsGRTmBj\":0.0001}],\"opreturn\":\"deadbeef\"}"
        if ( len > 0 )
        {
            argjson = cJSON_CreateObject();
            outputs = cJSON_CreateArray();
            if ( otheraddr != 0 && otheraddr[0] != 0 )
            {
                item = cJSON_CreateObject();
                jaddnum(item,otheraddr,dstr(10000));
                jaddi(outputs,item);
            }
            item = cJSON_CreateObject();
            jaddnum(item,coin->smartaddr,dstr(10000));
            jaddi(outputs,item);
            jadd(argjson,"outputs",outputs);
            jaddnum(argjson,"broadcast",1);
            jaddstr(argjson,"coin",coin->symbol);
            hexstr = calloc(1,len*2 + 1);
            init_hexbytes_noT(hexstr,linebuf,len);
            jaddstr(argjson,"opreturn",hexstr);
            free(hexstr);
            retstr = LP_withdraw(coin,argjson);
            free_json(argjson);
            if ( retstr != 0 )
            {
                //printf("mpnet.%s\n",retstr);
                free(retstr);
            }
        }
   }
}

cJSON *LP_mpnet_parse(struct iguana_info *coin,bits256 txid)
{
    cJSON *txobj,*vouts,*sobj,*argjson = 0; char *decodestr,*hexstr; uint8_t *buf,linebuf[8192]; int32_t len,n,hlen;
    if ( (txobj= LP_gettx("mpnet",coin->symbol,txid,0)) != 0 )
    {
        if ( (vouts= jarray(&n,txobj,"vout")) != 0 )
        {
            if ( (sobj= jobj(jitem(vouts,n-1),"scriptPubKey")) != 0 && (hexstr= jstr(sobj,"hex")) != 0 && (hlen= strlen(hexstr)) < sizeof(linebuf)*2 )
            {
                len = (hlen >> 1);
                decode_hex(linebuf,len,hexstr);
                buf = linebuf;
                //printf("hexstr.(%s)\n",hexstr);
                if ( *buf == 0x6a )
                {
                    buf++, len--;
                    if ( *buf == 0x4d )
                    {
                        buf++, len--;
                        n = buf[0] + buf[1]*256;
                        buf += 2, len -= 2;
                        if ( n == len )
                        {
                            if ( (decodestr= MMJSON_decode(buf,len)) != 0 )
                                argjson = cJSON_Parse(decodestr);
                        }
                    }
                }
                if ( 0 && argjson == 0 )
                    printf("unhandled case.(%s)\n",hexstr);
            }
        }
        if ( 0 && argjson == 0 )
            printf("unhandled tx.(%s)\n",jprint(txobj,0));
        free_json(txobj);
    }
    return(argjson);
}

// 2151978
// 404bc4ac452db07ed16376b3d7e77dbfc22b4a68f7243797125bd0d3bdddf8d1
// 893b46634456034a6d5d73b67026aa157b5e2addbfc6344dfbea6bae85f7dde0
// 717c7ef9de8504bd331f3ef52ed0a16ea0e070434e12cb4d63f5f081e999c43d dup

void LP_mpnet_process(void *ctx,char *myipaddr,int32_t pubsock,struct iguana_info *coin,bits256 txid)
{
    cJSON *argjson; char str[65];
    if ( LP_mpnet_find(txid) < 0 )
    {
        //printf("unique %s\n",bits256_str(str,txid));
        if ( (argjson= LP_mpnet_parse(coin,txid)) != 0 )
        {
            //printf("MPNET.(%s)\n",jprint(argjson,0));
            // TODO: Put the LP_tradecommand back when port LP_mpnet
            // LP_tradecommand(1,ctx,myipaddr,pubsock,argjson,0,0);
            free_json(argjson);
        }
        LP_mpnet_add(txid);
    }
}

cJSON *LP_mpnet_get(void *ctx,char *myipaddr,int32_t pubsock,struct iguana_info *coin)
{
    static int32_t lastheight; static bits256 lasthash;
    int32_t i,n=0,numtx,checkht = 0,height = 0; bits256 latesthash,hash,txid,zero; char hashstr[65],str[65]; cJSON *txs,*blockjson;
    memset(zero.bytes,0,sizeof(zero));
    latesthash = LP_getbestblockhash(coin);
    bits256_str(hashstr,latesthash);
    if ( (blockjson= LP_blockjson(&checkht,coin->symbol,hashstr,0)) != 0 )
    {
        hash = latesthash;
        while ( bits256_cmp(lasthash,hash) != 0 && n++ < 3 )
        {
            if ( (txs= jarray(&numtx,blockjson,"tx")) != 0 )
            {
                for (i=0; i<numtx; i++)
                {
                    txid = jbits256i(txs,i);
                    LP_mpnet_process(ctx,myipaddr,pubsock,coin,txid);
                    LP_mpnet_remove(txid);
                    //printf("ht.%d n.%d i.%d %s\n",checkht,n,i,bits256_str(str,txid));
                }
            }
            hash = jbits256(blockjson,"previousblockhash");
            free_json(blockjson);
            bits256_str(hashstr,hash);
            if ( (blockjson= LP_blockjson(&checkht,coin->symbol,hashstr,0)) == 0 )
                break;
        }
        lasthash = latesthash;
        if ( blockjson != 0 )
            free_json(blockjson);
        if ( (txs= LP_getmempool(coin->symbol,coin->smartaddr,zero,zero)) != 0 )
        {
            numtx = cJSON_GetArraySize(txs);
            for (i=0; i<numtx; i++)
            {
                txid = jbits256i(txs,i);
                LP_mpnet_process(ctx,myipaddr,pubsock,coin,txid);
                //printf("mp i.%d %s\n",i,bits256_str(str,txid));
            }
        }
    }
    return(0);
}

void LP_mpnet_check(void *ctx,char *myipaddr,int32_t pubsock)
{
    static uint32_t lasttime;
    struct iguana_info *coin = LP_coinfind("CHIPS");
    if ( coin != 0 && coin->inactive == 0 && time(NULL) > lasttime+5 )
    {
        LP_mpnet_get(ctx,myipaddr,pubsock,coin);
        lasttime = (uint32_t)time(NULL);
    }
}
