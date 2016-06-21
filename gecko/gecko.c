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

// code mempool and tx (payment and opreturn protocol)

// debug genesis balances
// debug remote <-> server and p2p network
// debug network port mode
// debug virtual + network port mode
// debug reorgs, detect when network is forked

// port DEX to use geckochain
// debug DEXchain

// code subchains synchronized with parent chain
// port pangea to use gecko with subchains
// debug pangea

// debug delayed PoW, code BTCD -> BTC, delegate selection using virtual coin stakes
// code datachain
//

#include "../iguana/iguana777.h"
#include "gecko_delayedPoW.c"
#include "gecko_headers.c"
#include "gecko_mempool.c"
#include "gecko_miner.c"
#include "gecko_blocks.c"

void gecko_iteration(struct supernet_info *myinfo,struct iguana_info *btcd,struct iguana_info *virt,int32_t maxmillis)
{
    char mineraddr[64]; int32_t hwmhdrsi,longesthdrsi;
    hwmhdrsi = virt->blocks.hwmchain.height / virt->chain->bundlesize;
    longesthdrsi = virt->longestchain / virt->chain->bundlesize;
    if ( hwmhdrsi <= longesthdrsi && virt->blocks.hwmchain.height < virt->longestchain-1 )
    {
        if ( time(NULL) > virt->hdrstime+3 )
        {
            if ( strcmp("BTCD",virt->symbol) == 0 )
                ;
            //fprintf(stderr,"r");
            gecko_requesthdrs(myinfo,virt,hwmhdrsi);
            //fprintf(stderr,"R");
            virt->hdrstime = (uint32_t)time(NULL);
        }
    }
    if ( btcd->RELAYNODE != 0 && virt->blocks.hwmchain.height >= virt->longestchain-virt->chain->bundlesize )
    {
        bitcoin_address(mineraddr,virt->chain->pubtype,myinfo->persistent_pubkey33,33);
        //fprintf(stderr,"mine.%s %s\n",virt->symbol,mineraddr);
        gecko_miner(myinfo,btcd,virt,maxmillis,myinfo->persistent_pubkey33);
    }
}

int32_t iguana_ROallocsize(struct iguana_info *virt)
{
    return(virt->chain->zcash != 0 ? sizeof(struct iguana_zblock) : sizeof(struct iguana_block));
}

bits256 calc_categoryhashes(bits256 *subhashp,char *category,char *subcategory)
{
    bits256 categoryhash;
    if ( category == 0 || category[0] == 0 || strcmp(category,"broadcast") == 0 )
        categoryhash = GENESIS_PUBKEY;
    else vcalc_sha256(0,categoryhash.bytes,(uint8_t *)category,(int32_t)strlen(category));
    if ( subhashp != 0 )
    {
        if ( subcategory == 0 || subcategory[0] == 0 || strcmp(subcategory,"broadcast") == 0 )
            *subhashp = GENESIS_PUBKEY;
        else vcalc_sha256(0,subhashp->bytes,(uint8_t *)subcategory,(int32_t)strlen(subcategory));
    }
    return(categoryhash);
}

struct gecko_chain *category_find(bits256 categoryhash,bits256 subhash)
{
    struct gecko_chain *cat=0,*sub = 0; bits256 hash;
    HASH_FIND(hh,Categories,categoryhash.bytes,sizeof(categoryhash),cat);
    if ( cat != 0 )
    {
        if ( bits256_nonz(subhash) > 0 && memcmp(GENESIS_PUBKEY.bytes,subhash.bytes,sizeof(subhash)) != 0 )
        {
            hash = subhash;
            HASH_FIND(hh,cat->subchains,hash.bytes,sizeof(hash),sub);
            if ( sub != 0 )
                return(sub);
        }
        return(cat);
    } //else printf("category_find.(%s) not found\n",bits256_str(str,categoryhash));//, getchar();
    return(0);
}

queue_t *category_Q(struct gecko_chain **catptrp,bits256 categoryhash,bits256 subhash)
{
    struct gecko_chain *cat;
    *catptrp = 0;
    if ( (cat= category_find(categoryhash,subhash)) != 0 )
    {
        *catptrp = cat;
        return(&cat->Q);
    }
    else return(0);
}

void *category_subscribe(struct supernet_info *myinfo,bits256 chainhash,bits256 keyhash)
{
    struct gecko_chain *chain,*subchain; bits256 hash;
    portable_mutex_lock(&myinfo->gecko_mutex);
    HASH_FIND(hh,Categories,chainhash.bytes,sizeof(chainhash),chain);
    if ( chain == 0 )
    {
        chain = mycalloc('c',1,sizeof(*chain));
        chain->hash = hash = chainhash;
        char str[65]; printf("ADD cat.(%s)\n",bits256_str(str,chainhash));
        HASH_ADD(hh,Categories,hash,sizeof(hash),chain);
    }
    if ( bits256_nonz(keyhash) > 0 && memcmp(GENESIS_PUBKEY.bytes,keyhash.bytes,sizeof(keyhash)) != 0 && chain != 0 )
    {
        HASH_FIND(hh,chain->subchains,keyhash.bytes,sizeof(keyhash),subchain);
        if ( subchain == 0 )
        {
            subchain = mycalloc('c',1,sizeof(*subchain));
            subchain->hash = hash = keyhash;
            char str[65],str2[65]; printf("subadd.(%s) -> (%s)\n",bits256_str(str,keyhash),bits256_str(str2,chainhash));
            HASH_ADD(hh,chain->subchains,hash,sizeof(hash),subchain);
        }
    }
    portable_mutex_unlock(&myinfo->gecko_mutex);
    return(chain);
}

struct gecko_chain *gecko_chain(struct supernet_info *myinfo,char chainname[GECKO_MAXNAMELEN],cJSON *valsobj)
{
    char *chainstr,*keystr; bits256 keyhash,chainhash; struct gecko_chain *chain;
    chainname[0] = 0;
    if ( (chainstr= jstr(valsobj,"chain")) == 0 )
        return(0);
    if ( (keystr= jstr(valsobj,"key")) != 0 )
        vcalc_sha256(0,keyhash.bytes,(uint8_t *)keystr,(int32_t)strlen(keystr));
    else keyhash = GENESIS_PUBKEY;
    vcalc_sha256(0,chainhash.bytes,(uint8_t *)chainstr,(int32_t)strlen(chainstr));
    if ( (chain= category_subscribe(myinfo,chainhash,keyhash)) == 0 )
        return(0);
    safecopy(chainname,chainstr,30), chainname[30] = 0;
    if ( keystr != 0 )
    {
        strcat(chainname,".");
        safecopy(chainname+strlen(chainname),keystr,GECKO_MAXNAMELEN-1-strlen(chainname));
    }
    return(chain);
}

/*int32_t gecko_chainvals(struct supernet_info *myinfo,char *CMD,cJSON *valsobj)
{
    struct iguana_info *virt; struct gecko_chain *chain; bits256 hash,prevhash; struct iguana_block *block; char chainname[GECKO_MAXNAMELEN];
    if ( strcmp(CMD,"SET") == 0 || strcmp(CMD,"GET") == 0 )
    {
        if ( (chain= gecko_chain(myinfo,chainname,valsobj)) == 0  || (virt= chain->info) == 0 )
            clonestr("{\"error\":\"cant find gecko chain\"}");
        if ( strcmp(CMD,"SET") == 0 )
        {
            hash = GENESIS_PUBKEY;
            if ( jobj(valsobj,"prev") != 0 )
            {
                prevhash = jbits256(valsobj,"prev");
                if ( (block= iguana_blockfind("basilisk",virt,prevhash)) == 0 )
                {
                    char str[65]; printf("warning couldnt find %s in %s\n",bits256_str(str,prevhash),chainname);
                    prevhash = virt->blocks.hwmchain.RO.hash2;
                }
            } else prevhash = virt->blocks.hwmchain.RO.hash2;
            hash = prevhash;
            if ( jobj(valsobj,"prev") != 0 )
                jdelete(valsobj,"prev");
        }
        return(0);
    }
    return(-1);
}*/

cJSON *gecko_genesisargs(char *symbol,char *chainname,char *chain,char *keystr,char *genesishash,char *genesisblock,char *magicstr,uint16_t port,uint16_t blocktime,char *nbitstr,char *pubval,char *p2shval,char *wifval,uint32_t isPoS)
{
    int32_t timespan,targetspacing; cJSON *argvals = cJSON_CreateObject();
    if ( genesishash != 0 && genesishash[0] != 0 )
        jaddstr(argvals,"genesishash",genesishash);
    if ( genesisblock != 0 && genesisblock[0] != 0  )
        jaddstr(argvals,"genesisblock",genesisblock);
    jaddstr(argvals,"netmagic",magicstr);
    jaddstr(argvals,"symbol",symbol);
    jaddstr(argvals,"name",chainname);
    if ( pubval == 0 || is_hexstr(pubval,0) != 2 )
        pubval = "00";
    jaddstr(argvals,"pubval",pubval);
    if ( p2shval == 0 || is_hexstr(p2shval,0) != 2 )
        p2shval = "05";
    jaddstr(argvals,"p2shval",p2shval);
    if ( wifval == 0 || is_hexstr(wifval,0) != 2 )
        wifval = "80";
    jaddstr(argvals,"wifval",wifval);
    if ( nbitstr == 0 || nbitstr[0] == 0 )
        nbitstr = GECKO_DEFAULTDIFFSTR;
    jaddstr(argvals,"nBits",nbitstr);
    jaddstr(argvals,"chain",chain);
    if ( keystr != 0 )
        jaddstr(argvals,"key",keystr);
    jaddnum(argvals,"isPoS",isPoS);
    //printf("argvals isPoS.%d\n",isPoS);
    if ( port == 0 )
    {
        jaddstr(argvals,"geckochain",chainname);
        jaddnum(argvals,"services",128);
    }
    else
    {
        jaddnum(argvals,"services",129);
        jaddnum(argvals,"portp2p",port);
    }
    if ( blocktime == 0 )
        blocktime = 1;
    jaddnum(argvals,"blocktime",blocktime);
    if ( blocktime != 0 )
    {
        if ( blocktime == 0xffff )
            targetspacing = 24 * 60 * 60; // one day
        else targetspacing = blocktime; // one minute
        jaddnum(argvals,"targetspacing",targetspacing);
        if ( (timespan= sqrt(604800 / targetspacing)) < 7 )
            timespan = 7;
        jaddnum(argvals,"targettimespan",targetspacing * timespan);
    }
    return(argvals);
}

cJSON *gecko_genesisjson(struct supernet_info *myinfo,struct iguana_info *btcd,int32_t isPoS,char *symbol,char *chainname,cJSON *valsobj,char *magicstr,uint16_t blocktime)
{
    char str2[64],hashstr[65],argbuf[1024],*pubstr,*p2shstr,*wifvalstr,*nbitstr,*blockstr; uint8_t buf[4]; int32_t i; uint32_t nBits; struct iguana_block genesis;
    if ( (nbitstr= jstr(valsobj,"nBits")) == 0 )
    {
        nBits = GECKO_DEFAULTDIFF;
        nbitstr = GECKO_DEFAULTDIFFSTR;
    }
    else
    {
        for (i=0; i<4; i++)
            decode_hex(&buf[3-i],1,&nbitstr[i*2]);
        memcpy(&nBits,buf,sizeof(nBits));
    }
    if ( (blocktime= juint(valsobj,"blocktime")) == 0 )
        blocktime = 1;
    if ( (pubstr= jstr(valsobj,"pubval")) == 0 )
        pubstr = "00";
    if ( (p2shstr= jstr(valsobj,"p2shval")) == 0 )
        p2shstr = "05";
    if ( (wifvalstr= jstr(valsobj,"wifval")) == 0 )
        wifvalstr = "80";
    printf("json netmagic.%s\n",magicstr);
    memset(&genesis,0,sizeof(genesis));
    genesis.RO.version = GECKO_DEFAULTVERSION;
    genesis.RO.bits = nBits;
    if ( (blockstr= gecko_createblock(myinfo,blocktime,0,btcd,isPoS,&genesis,symbol,0,0,10000,0,0)) != 0 )
    {
        bits256_str(hashstr,genesis.RO.hash2);
        sprintf(argbuf,"{\"isPoS\":%d,\"name\":\"%s\",\"symbol\":\"%s\",\"netmagic\":\"%s\",\"port\":%u,\"blocktime\":%u,\"pubval\":\"%s\",\"p2shval\":\"%s\",\"wifval\":\"%s\",\"isPoS\":%u,\"unitval\":\"%02x\",\"genesishash\":\"%s\",\"genesis\":{\"version\":1,\"timestamp\":%u,\"nBits\":\"%s\",\"nonce\":%d,\"merkle_root\":\"%s\"},\"genesisblock\":\"%s\"}",isPoS,chainname,symbol,magicstr,juint(valsobj,"port"),blocktime,pubstr,p2shstr,wifvalstr,juint(valsobj,"isPoS"),(nBits >> 24) & 0xff,hashstr,genesis.RO.timestamp,nbitstr,genesis.RO.nonce,bits256_str(str2,genesis.RO.merkle_root),blockstr);
        free(blockstr);
        printf("argbuf.(%s) hash.%s\n",argbuf,hashstr);
        return(cJSON_Parse(argbuf));
    } else return(cJSON_Parse("{\"error\":\"couldnt create block\"}"));
}

cJSON *gecko_genesisissue(char *symbol,char *chainname,char *chainstr,cJSON *valsobj)
{
    printf("issue blocktime.%d\n",juint(valsobj,"blocktime"));
    return(gecko_genesisargs(symbol,chainname,chainstr,jstr(valsobj,"key"),jstr(valsobj,"genesishash"),jstr(valsobj,"genesisblock"),jstr(valsobj,"netmagic"),juint(valsobj,"port"),juint(valsobj,"blocktime"),jstr(valsobj,"nBits"),jstr(valsobj,"pubval"),jstr(valsobj,"p2shval"),jstr(valsobj,"wifval"),juint(valsobj,"isPoS")));
}

struct iguana_info *basilisk_geckochain(struct supernet_info *myinfo,char *symbol,char *chainname,cJSON *valsobj)
{
    int32_t datalen,hdrsize,len=0; struct iguana_info *virt=0; char *hexstr; uint8_t hexbuf[8192],*ptr,*serialized; struct iguana_peer *addr; struct iguana_txblock txdata;
    portable_mutex_lock(&myinfo->gecko_mutex);
    printf("basilisk_geckochain symbol.%s chain.%s (%s)\n",symbol,chainname,jprint(valsobj,0));
    if ( iguana_coinfind(symbol) == 0 && (hexstr= jstr(valsobj,"genesisblock")) != 0 && (virt= iguana_coinadd(symbol,chainname,valsobj)) != 0 )
    {
        safecopy(virt->name,chainname,sizeof(virt->name));
        virt->chain = calloc(1,sizeof(*virt->chain));
        virt->enableCACHE = 1;
        serialized = get_dataptr(BASILISK_HDROFFSET,&ptr,&datalen,hexbuf,sizeof(hexbuf),hexstr);
        iguana_chaininit(virt->chain,1,valsobj);
        hdrsize = (virt->chain->zcash != 0) ? sizeof(struct iguana_msgblockhdr_zcash) : sizeof(struct iguana_msgblockhdr);
        if ( gecko_blocknonce_verify(virt,serialized,hdrsize,virt->chain->nBits,0,0) > 0 )
        {
            virt->chain->genesishash2 = iguana_calcblockhash(symbol,virt->chain->hashalgo,serialized,hdrsize);
            memcpy(virt->chain->genesis_hashdata,virt->chain->genesishash2.bytes,sizeof(virt->chain->genesishash2));
            if ( ptr != 0 )
                free(ptr);
            if ( virt->TXMEM.ptr == 0 )
                iguana_meminit(&virt->TXMEM,virt->name,0,IGUANA_MAXPACKETSIZE * 2,0);
            virt->chain->genesis_hex = clonestr(hexstr);
            virt->MAXPEERS = 0;
            virt->RELAYNODE = 1;
            virt->virtualchain = 1;
            addr = &virt->internaladdr;
            strcpy(virt->VALIDATEDIR,GLOBAL_VALIDATEDIR);
            printf("GLOBAL_VALIDATEDIR.(%s) (%s)\n",GLOBAL_VALIDATEDIR,virt->VALIDATEDIR);
            iguana_callcoinstart(myinfo,virt);
            iguana_initpeer(virt,addr,calc_ipbits("127.0.0.1"));
            iguana_peerslotinit(virt,addr,IGUANA_MAXPEERS,addr->ipbits);
            if ( addr->blockspace == 0 )
                addr->blockspace = calloc(1,IGUANA_MAXPACKETSIZE + 8192);
            if ( addr->RAWMEM.ptr == 0 )
                iguana_meminit(&addr->RAWMEM,virt->symbol,0,IGUANA_MAXPACKETSIZE * 2,0);
            if ( addr->TXDATA.ptr == 0 )
                iguana_meminit(&addr->TXDATA,"txdata",0,IGUANA_MAXPACKETSIZE * 2,0);
            if ( addr->HASHMEM.ptr == 0 )
                iguana_meminit(&addr->HASHMEM,"HASHPTRS",0,256,0);//IGUANA_MAXPACKETSIZE*16,0);
            iguana_bundlesload(myinfo,virt);
            if ( virt->blocks.hwmchain.height == 0 )
            {
                memset(&txdata,0,sizeof(txdata));
                iguana_gentxarray(virt,&virt->TXMEM,&txdata,&len,serialized,datalen);
                txdata.zblock.height = 0;
                txdata.zblock.RO.allocsize = iguana_ROallocsize(virt);
                gecko_hwmset(myinfo,virt,&txdata,virt->TXMEM.ptr,serialized,datalen,txdata.numtxids);
            }
            virt->started = virt;
            virt->active = (uint32_t)time(NULL);
        } else printf("error validating nonce\n");
    }
    portable_mutex_unlock(&myinfo->gecko_mutex);
    return(virt);
}

char *basilisk_respond_newgeckochain(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 prevhash,int32_t from_basilisk)
{
    struct iguana_info *virt,*btcd; struct gecko_chain *chain; char fname[512],*symbol,*retstr,*chainstr,chainname[GECKO_MAXNAMELEN],*genesises; cJSON *chainjson,*retjson,*genesisjson; long filesize; FILE *fp;
    if ( (chain= gecko_chain(myinfo,chainname,valsobj)) != 0 && (virt= chain->info) != 0 )
    {
        //printf("%s already exists\n",chainname);
        return(clonestr("{\"error\":\"cant create duplicate geckochain\"}"));
    }
    if ( (btcd= iguana_coinfind("BTCD")) != 0 && (symbol= jstr(valsobj,"symbol")) != 0 && (chainstr= jstr(valsobj,"chain")) != 0 )
    {
        if ( (virt= basilisk_geckochain(myinfo,symbol,chainname,valsobj)) != 0 )
        {
            chain->info = virt;
            if ( (retjson= gecko_genesisissue(symbol,chainname,chainstr,valsobj)) != 0 )
            {
                jaddstr(retjson,"result","success");
                retstr = jprint(retjson,0);
                sprintf(fname,"genesis/%s",symbol);
                genesisjson = 0;
                filesize = 0;
                if ( (fp= fopen(fname,"wb")) != 0 )
                {
                    if ( fwrite(retstr,1,strlen(retstr),fp) == strlen(retstr) )
                    {
                        if ( (genesises= OS_filestr(&filesize,"genesis/list")) != 0 )
                        {
                            genesisjson = cJSON_Parse(genesises);
                            free(genesises);
                        } else genesisjson = cJSON_CreateArray();
                        chainjson = cJSON_CreateObject();
                        jaddstr(chainjson,"chain",chainname);
                        jaddstr(chainjson,"symbol",symbol);
                        jaddstr(chainjson,"agent","basilisk");
                        jaddstr(chainjson,"method","newgeckochain");
                        jadd(chainjson,"vals",retjson);
                        jaddi(genesisjson,chainjson);
                    }
                    fclose(fp);
                }
                if ( genesisjson != 0 )
                {
                    genesises = jprint(genesisjson,1);
                    if ( strlen(genesises) > filesize )
                    {
                        if ( (fp= fopen("genesis/list","wb")) != 0 )
                        {
                            fwrite(genesises,1,strlen(genesises),fp);
                            fclose(fp);
                        }
                    }
                } else free_json(retjson);
                return(retstr);
            } else return(clonestr("{\"error\":\"couldnt create gecko genesis\"}"));
        }
    }
    return(clonestr("{\"error\":-22}"));
}

int32_t gecko_genesises(struct supernet_info *myinfo,cJSON *array)
{
    char *chainstr,chainname[GECKO_MAXNAMELEN],*symbol; int32_t i,n,num=0; cJSON *item,*valsobj; struct iguana_info *btcd,*virt; struct gecko_chain *chain;
    if ( (btcd= iguana_coinfind("BTCD")) == 0 )
        return(0);
    if ( array != 0 && (n= cJSON_GetArraySize(array)) != 0 )
    {
        for (i=0; i<n; i++)
        {
            item = jitem(array,i);
            valsobj = jobj(item,"vals");
            if ( valsobj != 0 && (chainstr= jstr(item,"chain")) != 0 && (symbol= jstr(item,"symbol")) != 0 )
            {
                if ( (chain= gecko_chain(myinfo,chainname,valsobj)) != 0 && (virt= chain->info) != 0 )
                {
                    //printf("%s %s already exists\n",chainname,symbol);
                    continue;
                }
                if ( (virt= basilisk_geckochain(myinfo,symbol,chainname,valsobj)) != 0 )
                {
                    chain->info = virt;
                    num++;
                }
            }
        }
    }
    return(num);
}

char *basilisk_respond_geckogenesis(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 txid,int32_t from_basilisk)
{
    long filesize;
    return(OS_filestr(&filesize,"genesis/list"));
}

char *basilisk_standardreturn(char *CMD,char *type,struct iguana_info *virt,uint8_t *serialized,int32_t datalen,bits256 hash)
{
    char space[16384],*allocstr = 0; cJSON *retjson = cJSON_CreateObject();
    if ( datalen > 0 && basilisk_addhexstr(&allocstr,retjson,space,sizeof(space),serialized,datalen) != 0 )
    {
        jaddstr(retjson,"CMD",CMD);
        jaddstr(retjson,"type",type);
        jaddstr(retjson,"symbol",virt->symbol);
        //jaddnum(retjson,"longest",virt->longestchain);
        jaddnum(retjson,"hwm",virt->blocks.hwmchain.height);
        jaddnum(retjson,"datalen",datalen);
        jaddbits256(retjson,"chaintip",virt->blocks.hwmchain.RO.hash2);
        jaddbits256(retjson,"hash",hash);
    } else jaddstr(retjson,"error","no data to send");
    if ( allocstr != 0 )
        free(allocstr);
    return(jprint(retjson,1));
}

char *basilisk_respond_geckoget(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash2,int32_t from_basilisk)
{
    int32_t (*getfunc)(struct supernet_info *myinfo,struct iguana_info *virt,uint8_t *serialized,int32_t maxsize,cJSON *valsobj,bits256 hash2);
    uint8_t *serialized; int32_t maxsize; char *symbol,*type; struct iguana_info *virt;
    if ( (type= jstr(valsobj,"type")) != 0 )
    {
        if ( strcmp(type,"HDR") == 0 )
            getfunc = basilisk_respond_geckogetheaders;
        else if ( strcmp(type,"BLK") == 0 )
            getfunc = basilisk_respond_geckogetblock;
        else if ( strcmp(type,"GTX") == 0 )
            getfunc = basilisk_respond_geckogettx;
        else return(clonestr("{\"error\":\"invalid geckoget type, mustbe (HDR or BLK or GTX)\"}"));
        if ( (serialized= ((struct iguana_peer *)addr)->blockspace) == 0 )
            return(clonestr("{\"error\":\"peer has no blockspace\"}"));
        maxsize = IGUANA_MAXPACKETSIZE;
        if ( (symbol= jstr(valsobj,"symbol")) != 0 && (virt= iguana_coinfind(symbol)) != 0 )
        {
            datalen = (*getfunc)(myinfo,virt,serialized,maxsize,valsobj,hash2);
            printf("return datalen.%d for %s\n",datalen,type);
            return(basilisk_standardreturn(CMD,type,virt,serialized,datalen,hash2));
        } else return(clonestr("{\"error\":\"couldt find gecko chain\"}"));
    } else return(clonestr("{\"error\":\"invalid geckoget type, mustbe (HDR or BLK or GTX)\"}"));
}

#include "../includes/iguana_apidefs.h"
#include "../includes/iguana_apideclares.h"

HASH_ARRAY_STRING(basilisk,sequence,hash,vals,hexstr)
{
    return(basilisk_standardservice("SEQ",myinfo,hash,vals,hexstr,1));
}

HASH_ARRAY_STRING(basilisk,newgeckochain,hash,vals,hexstr)
{
    char chainname[GECKO_MAXNAMELEN],magicstr[9],*retstr=0,*symbol,*chainstr; struct iguana_info *btcd; cJSON *argjson,*argvals,*retjson=0; int32_t i,isPoS; uint32_t magic; struct gecko_chain *chain;
    if ( (btcd= iguana_coinfind("BTCD")) != 0 && (symbol= jstr(vals,"symbol")) != 0 && (chainstr= jstr(vals,"chain")) != 0 )
    {
        if ( iguana_coinfind(symbol) == 0 && (chain= gecko_chain(myinfo,chainname,vals)) != 0 && chain->info != 0 )
        {
            printf("%s already exists\n",chainname);
            return(clonestr("{\"error\":\"cant create duplicate geckochain\"}"));
        }
        if ( jobj(vals,"netmagic") == 0 )
        {
            OS_randombytes((void *)&magic,sizeof(magic));
            for (i=0; i<sizeof(magic); i++)
                ((uint8_t *)&magic)[i] |= 0x80;
            init_hexbytes_noT(magicstr,(void *)&magic,sizeof(magic));
        } else safecopy(magicstr,jstr(vals,"netmagic"),sizeof(magicstr));
        if ( (isPoS= juint(vals,"isPoS")) == 0 )
            isPoS = 1;
        //printf("netmagic.%s\n",magicstr);
        if ( (argjson= gecko_genesisjson(myinfo,btcd,isPoS,symbol,chainname,vals,magicstr,juint(vals,"blocktime"))) != 0 )
        {
            argvals = gecko_genesisissue(symbol,chainname,chainstr,argjson);
            if ( btcd->RELAYNODE != 0 || btcd->VALIDATENODE != 0 )
            {
                basilisk_wait(myinfo,0);
                retstr = basilisk_respond_newgeckochain(myinfo,"NEW",0,0,0,argvals,0,0,GENESIS_PUBKEY,0);
            }
            if ( retstr == 0 )
                retstr = basilisk_standardservice("NEW",myinfo,GENESIS_PUBKEY,argvals,0,1);
            free_json(argvals);
            if ( (argvals= cJSON_Parse(retstr)) != 0 )
            {
                if ( jobj(argvals,"result") != 0 && strcmp(jstr(argvals,"result"),"success") == 0 )
                {
                    if ( basilisk_geckochain(myinfo,symbol,chainname,argvals) != 0 )
                        jaddstr(argvals,"status","active");
                } else jaddstr(argvals,"error","couldnt initialize geckochain");
                free(retstr);
                return(jprint(argvals,1));
            }
            if ( retjson != 0 )
                free_json(retjson);
            free_json(argvals);
            return(retstr);
        } else return(clonestr("{\"error\":\"couldnt create genesis_block\"}"));
    }
    return(clonestr("{\"error\":\"need symbol and chain and BTCD to create new gecko chain\"}"));
}

char *gecko_sendrawtransaction(struct supernet_info *myinfo,char *symbol,uint8_t *data,int32_t datalen,bits256 txid,cJSON *vals,char *signedtx)
{
    char *retstr = 0; struct iguana_info *virt,*btcd = iguana_coinfind("BTCD");
    virt = iguana_coinfind(symbol);
    if ( btcd != 0 && (btcd->RELAYNODE != 0 || btcd->VALIDATENODE != 0) )
    {
        basilisk_wait(myinfo,virt);
        retstr = basilisk_respond_geckotx(myinfo,"GTX",0,0,0,vals,data,datalen,txid,0);
    }
    if ( retstr == 0 )
        retstr = basilisk_standardservice("GTX",myinfo,txid,vals,signedtx,1);
    return(retstr);
}

HASH_ARRAY_STRING(basilisk,geckotx,hash,vals,hexstr)
{
    struct iguana_info *btcd; char *retstr=0,*symbol; uint8_t *data,*allocptr,space[4096]; int32_t datalen; bits256 txid;
    if ( (btcd= iguana_coinfind("BTCD")) != 0 && (symbol= jstr(vals,"symbol")) != 0 )
    {
        if ( (data= get_dataptr(BASILISK_HDROFFSET,&allocptr,&datalen,space,sizeof(space),hexstr)) != 0 )
        {
            txid = bits256_doublesha256(0,data,datalen);
            retstr = gecko_sendrawtransaction(myinfo,symbol,data,datalen,txid,vals,hexstr);
        } else retstr = clonestr("{\"error\":\"no tx submitted\"}");
        if ( allocptr != 0 )
            free(allocptr);
        if ( retstr == 0 )
            retstr = clonestr("{\"error\":\"couldnt create geckotx\"}");
        return(retstr);
    } return(clonestr("{\"error\":\"need symbol and chain and BTCD to create new gecko tx\"}"));
}

HASH_ARRAY_STRING(basilisk,geckoblock,hash,vals,hexstr)
{
    return(clonestr("{\"error\":\"geckoblock is an internal reporting function\"}"));
}

HASH_ARRAY_STRING(basilisk,geckoheaders,hash,vals,hexstr)
{
    return(clonestr("{\"error\":\"geckoheaders is an internal reporting function\"}"));
}

HASH_ARRAY_STRING(basilisk,geckoget,hash,vals,hexstr)
{
    struct iguana_info *btcd,*virt; char *symbol;
    if ( (btcd= iguana_coinfind("BTCD")) != 0 && (symbol= jstr(vals,"symbol")) != 0 )
    {
        if ( (virt= iguana_coinfind(symbol)) != 0 )
        {
            basilisk_wait(myinfo,virt);
            return(basilisk_respond_geckoget(myinfo,"GET",&coin->internaladdr,remoteaddr,0,vals,0,0,hash,0));
        } else return(clonestr("{\"error\":\"geckoget needs virtualchain\"}"));
    }
    return(clonestr("{\"error\":\"geckoget needs BTCD\"}"));
}

HASH_ARRAY_STRING(basilisk,geckogenesis,hash,vals,hexstr)
{
    long filesize; int32_t i,j,n,m; struct iguana_info *btcd; char *ref,*symbol,*retstr=0; cJSON *item,*array = 0,*arrayB = 0; FILE *fp;
    if ( (btcd= iguana_coinfind("BTCD")) != 0 )
    {
        if ( (retstr= basilisk_standardservice("GEN",myinfo,hash,vals,hexstr,1)) != 0 )
        {
            myinfo->genesisresults++;
            arrayB = cJSON_Parse(retstr);
            free(retstr);
        }
        if ( btcd->RELAYNODE != 0 || btcd->VALIDATENODE != 0 )
        {
            if ( (retstr= OS_filestr(&filesize,"genesis/list")) != 0 )
            {
                array = cJSON_Parse(retstr);
                free(retstr);
            }
            if ( array == 0 )
                array = arrayB;
            else if ( arrayB != 0 )
            {
                if ( (n= cJSON_GetArraySize(array)) > 0 )
                {
                    if ( (m= cJSON_GetArraySize(arrayB)) > 0 )
                    {
                        for (j=0; j<m; j++)
                        {
                            item = jitem(arrayB,j);
                            if ( jobj(item,"error") == 0 && (symbol= jstr(item,"symbol")) != 0 )
                            {
                                for (i=0; i<n; i++)
                                {
                                    if ( (ref= jstr(jitem(array,i),"symbol")) != 0 && strcmp(symbol,ref) == 0 )
                                        break;
                                }
                                if ( i == n )
                                    jaddi(array,jduplicate(item));
                            }
                        }
                    }
                }
                free_json(arrayB);
            }
        } else array = arrayB;
        if ( array != 0 )
        {
            gecko_genesises(myinfo,array);
            retstr = jprint(array,1);
            if ( (ref= OS_filestr(&filesize,"genesis/list")) == 0 || strlen(ref) < strlen(retstr) )
            {
                if ( (fp= fopen("genesis/list","wb")) != 0 )
                {
                    fwrite(retstr,1,strlen(retstr),fp);
                    fclose(fp);
                }
            }
            if ( ref != 0 )
                free(ref);
            return(retstr);
        }
    }
    return(clonestr("{\"error\":\"need BTCD to get geckogenesis list\"}"));
}
#include "../includes/iguana_apiundefs.h"


