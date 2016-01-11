/******************************************************************************
 * Copyright © 2014-2015 The SuperNET Developers.                             *
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

#define CHROMEAPP_NAME iguana
#define CHROMEAPP_STR "iguana"
#define CHROMEAPP_CONF "iguana.conf"
#define CHROMEAPP_MAIN iguana_main
#define CHROMEAPP_JSON iguana_JSON
#define CHROMEAPP_HANDLER Handler_iguana

#include "../pnacl_main.h"
#include "iguana777.h"
#include "SuperNET.h"

// ALL globals must be here!
struct iguana_info *Coins[IGUANA_MAXCOINS];
int32_t USE_JAY,FIRST_EXTERNAL,IGUANA_disableNXT,Debuglevel;
uint32_t prices777_NXTBLOCK,MAX_DEPTH = 100;
char NXTAPIURL[256],IGUANA_NXTADDR[256],IGUANA_NXTACCTSECRET[256];
uint64_t IGUANA_MY64BITS;
queue_t helperQ,jsonQ,finishedQ;
static int32_t initflag;
#ifdef __linux__
int32_t IGUANA_NUMHELPERS = 4;
#else
int32_t IGUANA_NUMHELPERS = 1;
#endif

char *hash_parser(struct supernet_info *myinfo,char *hashname,cJSON *json,char *remoteaddr)
{
    int32_t i,len,iter,n; uint8_t databuf[512];
    char hexstr[1025],*password,*name,*msg;
    typedef void (*hashfunc)(char *hexstr,uint8_t *buf,uint8_t *msg,int32_t len);
    typedef char *(*hmacfunc)(char *dest,char *key,int32_t key_size,char *message);
    struct hashfunc_entry { char *name; hashfunc hashfunc; };
    struct hmacfunc_entry { char *name; hmacfunc hmacfunc; };
    struct hashfunc_entry hashes[] = { {"NXT",calc_NXTaddr}, {"curve25519",calc_curve25519_str }, {"base64_encode",calc_base64_encodestr}, {"base64_decode",calc_base64_decodestr}, {"crc32",calc_crc32str}, {"rmd160_sha256",rmd160ofsha256}, {"sha256_sha256",sha256_sha256}, {"sha256",vcalc_sha256}, {"sha512",calc_sha512}, {"sha384",calc_sha384}, {"sha224",calc_sha224}, {"rmd160",calc_rmd160}, {"rmd256",calc_rmd256}, {"rmd320",calc_rmd320}, {"rmd128",calc_rmd128}, {"sha1",calc_sha1}, {"md5",calc_md5str}, {"tiger",calc_tiger}, {"whirlpool",calc_whirlpool} };
    struct hmacfunc_entry hmacs[] = { {"hmac_sha256",hmac_sha256_str}, {"hmac_sha512",hmac_sha512_str}, {"hmac_sha384",hmac_sha384_str}, {"hmac_sha224",hmac_sha224_str}, {"hmac_rmd160",hmac_rmd160_str}, {"hmac_rmd256",hmac_rmd256_str}, {"hmac_rmd320",hmac_rmd320_str}, {"hmac_rmd128",hmac_rmd128_str}, {"hmac_sha1",hmac_sha1_str}, {"hmac_md5",hmac_md5_str}, {"hmac_tiger",hmac_tiger_str}, {"hmac_whirlpool",hmac_whirlpool_str} };
    if ( (msg= jstr(json,"message")) == 0 )
        return(clonestr("{\"error\":\"no message to hash\"}"));
    password = jstr(json,"password");
    n = (int32_t)sizeof(hashes)/sizeof(*hashes);
    printf("msg.(%s) password.(%s)\n",msg,password!=0?password:"");
    for (iter=0; iter<2; iter++)
    {
        for (i=0; i<n; i++)
        {
            name = (iter == 0) ? hashes[i].name : hmacs[i].name;
            printf("iter.%d i.%d (%s) vs (%s) %d\n",iter,i,name,hashname,strcmp(hashname,name) == 0);
            if ( strcmp(hashname,name) == 0 )
            {
                json = cJSON_CreateObject();
                len = (int32_t)strlen(msg);
                if ( iter == 0 )
                    (*hashes[i].hashfunc)(hexstr,databuf,(uint8_t *)msg,len);
                else (*hmacs[i].hmacfunc)(hexstr,password,(int32_t)strlen(password),msg);
                jaddstr(json,"result","hash calculated");
                jaddstr(json,"message",msg);
                jaddstr(json,name,hexstr);
                return(jprint(json,1));
            }
        }
        n = (int32_t)sizeof(hmacs)/sizeof(*hmacs);
    }
    return(clonestr("{\"error\":\"cant find hash function\"}"));
}

char *InstantDEX_parser(struct supernet_info *myinfo,char *method,cJSON *json,char *remoteaddr)
{
    return(clonestr("{\"error\":\"InstantDEX API is not yet\"}"));
}

char *jumblr_parser(struct supernet_info *myinfo,char *method,cJSON *json,char *remoteaddr)
{
    return(clonestr("{\"error\":\"jumblr API is not yet\"}"));
}

char *pangea_parser(struct supernet_info *myinfo,char *method,cJSON *json,char *remoteaddr)
{
    return(clonestr("{\"error\":\"jumblr API is not yet\"}"));
}

char *SuperNET_jsonstr(struct supernet_info *myinfo,char *jsonstr,char *remoteaddr)
{
    cJSON *json; char *agent,*method;
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        method = jstr(json,"method");
        if ( (agent= jstr(json,"agent")) != 0 && method != 0 )
        {
            if ( strcmp(agent,"iguana") == 0 )
                return(iguana_parser(myinfo,method,json,remoteaddr));
            else if ( strcmp(agent,"ramchain") == 0 )
                return(ramchain_parser(myinfo,method,json,remoteaddr));
            else if ( strcmp(agent,"InstantDEX") == 0 )
                return(InstantDEX_parser(myinfo,method,json,remoteaddr));
            else if ( strcmp(agent,"pangea") == 0 )
                return(pangea_parser(myinfo,method,json,remoteaddr));
            else if ( strcmp(agent,"jumblr") == 0 )
                return(jumblr_parser(myinfo,method,json,remoteaddr));
            else if ( strcmp(agent,"hash") == 0 )
                return(hash_parser(myinfo,method,json,remoteaddr));
        }
        else if ( method != 0 && is_bitcoinrpc(method) )
            return(iguana_bitcoinRPC(myinfo,method,json,remoteaddr));
        return(clonestr("{\"error\":\"need both agent and method\"}"));
    }
    return(clonestr("{\"error\":\"couldnt parse SuperNET_JSON\"}"));
}

struct iguana_jsonitem { struct queueitem DL; struct supernet_info *myinfo; uint32_t fallback,expired,allocsize; char **retjsonstrp; char remoteaddr[64]; char jsonstr[]; };

int32_t iguana_jsonQ()
{
    struct iguana_jsonitem *ptr;
    if ( (ptr= queue_dequeue(&finishedQ,0)) != 0 )
    {
        if ( ptr->expired != 0 )
        {
            *ptr->retjsonstrp = clonestr("{\"error\":\"request timeout\"}");
            printf("garbage collection: expired.(%s)\n",ptr->jsonstr);
            myfree(ptr,ptr->allocsize);
        } else queue_enqueue("finishedQ",&finishedQ,&ptr->DL,0);
    }
    if ( (ptr= queue_dequeue(&jsonQ,0)) != 0 )
    {
        //printf("process.(%s)\n",ptr->jsonstr);
        if ( (*ptr->retjsonstrp= SuperNET_jsonstr(ptr->myinfo,ptr->jsonstr,ptr->remoteaddr)) == 0 )
            *ptr->retjsonstrp = clonestr("{\"error\":\"null return from iguana_jsonstr\"}");
        //printf("finished.(%s)\n",ptr->jsonstr);
        queue_enqueue("finishedQ",&finishedQ,&ptr->DL,0);
        return(1);
    }
    return(0);
}

char *iguana_blockingjsonstr(struct supernet_info *myinfo,char *jsonstr,uint64_t tag,int32_t maxmillis,char *remoteaddr)
{
    struct iguana_jsonitem *ptr; char *retjsonstr = 0; int32_t len,allocsize; double expiration;
    expiration = OS_milliseconds() + maxmillis;
    //printf("blocking case.(%s)\n",jsonstr);
    len = (int32_t)strlen(jsonstr);
    allocsize = sizeof(*ptr) + len + 1;
    ptr = mycalloc('J',1,allocsize);
    ptr->allocsize = allocsize;
    ptr->myinfo = myinfo;
    ptr->retjsonstrp = &retjsonstr;
    safecopy(ptr->remoteaddr,remoteaddr,sizeof(ptr->remoteaddr));
    memcpy(ptr->jsonstr,jsonstr,len+1);
    queue_enqueue("jsonQ",&jsonQ,&ptr->DL,0);
    while ( OS_milliseconds() < expiration )
    {
        usleep(100);
        if ( retjsonstr != 0 )
        {
            printf("blocking retjsonstr.(%s)\n",retjsonstr);
            queue_delete(&finishedQ,&ptr->DL,allocsize,1);
            return(retjsonstr);
        }
        usleep(1000);
    }
    //printf("(%s) expired\n",jsonstr);
    ptr->expired = (uint32_t)time(NULL);
    return(clonestr("{\"error\":\"iguana jsonstr expired\"}"));
}

char *SuperNET_JSON(struct supernet_info *myinfo,cJSON *json,char *remoteaddr)
{
    cJSON *retjson; uint64_t tag; uint32_t timeout; char *jsonstr; char *retjsonstr,*retstr = 0;
    if ( json != 0 )
    {
        /*if ( localaccess != 0 && (method= jstr(json,"method")) != 0 && strcmp(method,"addcoin") == 0 )
        {
            if ( (retval= iguana_launchcoin(jstr(json,"coin"),json)) > 0 )
                return(clonestr("{\"result\":\"launched coin\"}"));
            else if ( retval == 0 ) return(clonestr("{\"result\":\"coin already launched\"}"));
            else return(clonestr("{\"error\":\"error launching coin\"}"));
        }*/
        if ( (tag= j64bits(json,"tag")) == 0 )
            OS_randombytes((uint8_t *)&tag,sizeof(tag));
        /*if ( (symbol= jstr(json,"coin")) != 0 )
        {
            coin = iguana_coinfind(symbol);
            if ( coin != 0 && localaccess != 0 && coin->launched == 0 )
                iguana_launchcoin(symbol,json);
        }*/
        if ( (timeout= juint(json,"timeout")) == 0 )
            timeout = IGUANA_JSONTIMEOUT;
        jsonstr = jprint(json,0);
        if ( (retjsonstr= iguana_blockingjsonstr(myinfo,jsonstr,tag,timeout,remoteaddr)) != 0 )
        {
            //printf("retjsonstr.(%s)\n",retjsonstr);
            if ( (retjson= cJSON_Parse(retjsonstr)) == 0 )
                retjson = cJSON_Parse("{\"error\":\"cant parse retjsonstr\"}");
            jdelete(retjson,"tag");
            jadd64bits(retjson,"tag",tag);
            retstr = jprint(retjson,1);
            //printf("retstr.(%s) retjsonstr.%p retjson.%p\n",retstr,retjsonstr,retjson);
            free(retjsonstr);//,strlen(retjsonstr)+1);
        }
        free(jsonstr);
    } else retstr = clonestr("{\"error\":\"cant parse JSON\"}");
    if ( retstr == 0 )
        retstr = clonestr("{\"error\":\"null return\"}");
    return(retstr);
}

char *iguana_JSON(char *jsonstr)
{
    char *retstr=0; cJSON *json;
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        retstr = SuperNET_JSON(0,json,"127.0.0.1");
        free_json(json);
    }
    if ( retstr == 0 )
        retstr = clonestr("{\"error\":\"cant parse jsonstr from pnacl\"}");
    return(retstr);
}

char *SuperNET_p2p(struct iguana_info *coin,int32_t *delaymillisp,char *ipaddr,uint8_t *data,int32_t datalen)
{
    cJSON *json,*retjson; char *agent,*method,*retstr = 0;
    if ( (json= cJSON_Parse((char *)data)) != 0 )
    {
        printf("GOT >>>>>>>> SUPERNET P2P.(%s) from.%s\n",(char *)data,coin->symbol);
        if ( (agent= jstr(json,"agent")) != 0 && (method= jstr(json,"method")) != 0 )
        {
            jaddstr(json,"fromp2p",coin->symbol);
            if ( (retstr= SuperNET_JSON(0,json,ipaddr)) != 0 )
            {
                if ( (retjson= cJSON_Parse(retstr)) != 0 )
                {
                    if ( jobj(retjson,"result") != 0 || jobj(retjson,"error") != 0 || jobj(retjson,"method") == 0 )
                    {
                        free(retstr);
                        retstr = 0;
                    }
                    free_json(retjson);
                }
            }
        }
        free_json(json);
    }
    return(retstr);
}

void iguana_main(void *arg)
{
    struct supernet_info MYINFO; char helperstr[64],*helperargs,*coinargs=0,*secret,*jsonstr = arg;
    int32_t i,len,flag; cJSON *json; uint8_t secretbuf[512];
    mycalloc(0,0,0);
    iguana_initQ(&helperQ,"helperQ");
    OS_ensure_directory("confs");
    OS_ensure_directory("DB");
    OS_ensure_directory("tmp");
    memset(&MYINFO,0,sizeof(MYINFO));
    if ( jsonstr != 0 && (json= cJSON_Parse(jsonstr)) != 0 )
    {
        if ( jobj(json,"numhelpers") != 0 )
            IGUANA_NUMHELPERS = juint(json,"numhelpers");
        if ( (secret= jstr(json,"secret")) != 0 )
        {
            len = (int32_t)strlen(secret);
            if ( is_hexstr(secret,0) != 0 && len == 128 )
            {
                len >>= 1;
                decode_hex(secretbuf,len,secret);
            } else vcalc_sha256(0,secretbuf,(void *)secret,len), len = sizeof(bits256);
            memcpy(MYINFO.privkey.bytes,secretbuf,sizeof(MYINFO.privkey));
        }
        if ( jobj(json,"coins") != 0 )
            coinargs = jsonstr;
    }
    if ( IGUANA_NUMHELPERS == 0 )
        IGUANA_NUMHELPERS = 1;
    for (i=0; i<IGUANA_NUMHELPERS; i++)
    {
        sprintf(helperstr,"{\"name\":\"helper.%d\"}",i);
        helperargs = clonestr(helperstr);
        iguana_launch(iguana_coinadd("BTCD"),"iguana_helper",iguana_helper,helperargs,IGUANA_PERMTHREAD);
    }
    iguana_launch(iguana_coinadd("BTCD"),"rpcloop",iguana_rpcloop,iguana_coinadd("BTCD"),IGUANA_PERMTHREAD);
    if ( coinargs != 0 )
        iguana_launch(iguana_coinadd("BTCD"),"iguana_coins",iguana_coins,coinargs,IGUANA_PERMTHREAD);
    else if ( 1 )
    {
#ifdef __APPLE__
        sleep(1);
        char *str;
        if ( (str= SuperNET_JSON(&MYINFO,cJSON_Parse("{\"agent\":\"iguana\",\"method\":\"addcoin\",\"services\":128,\"maxpeers\":16,\"coin\":\"BTCD\",\"active\":1}"),0)) != 0 )
        {
            printf("got.(%s)\n",str);
            free(str);
        }
#endif
    }
    if ( arg != 0 )
        SuperNET_JSON(&MYINFO,cJSON_Parse(arg),0);
    //init_InstantDEX();
    while ( 1 )
    {
        //flag = 0;
        //for (i=0; i<sizeof(Coins)/sizeof(*Coins); i++)
        //    if ( Coins[i] != 0 && Coins[i]->symbol[0] != 0 )
        //        flag += iguana_processjsonQ(Coins[i]);
        flag = iguana_jsonQ();
        if ( flag == 0 )
            usleep(100000);
    }
}

