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
//  main.c
//  marketmaker
//
//  Copyright © 2017 SuperNET. All rights reserved.
//


void PNACL_message(char *arg,...)
{
    
}
#define FROM_MARKETMAKER

#include <stdio.h>
#include <stdint.h>
#ifndef NATIVE_WINDOWS
#include "OS_portable.h"
#else
#include "../../crypto777/OS_portable.h"
#endif // !_WIN_32

uint32_t DOCKERFLAG;
#define MAX(a,b) ((a) > (b) ? (a) : (b))
char *stats_JSON(void *ctx,char *myipaddr,int32_t pubsock,cJSON *argjson,char *remoteaddr,uint16_t port);
#include "stats.c"
void LP_priceupdate(char *base,char *rel,double price,double avebid,double aveask,double highbid,double lowask,double PAXPRICES[32]);

//defined(__APPLE__) ||
#ifdef FROM_JS // defined(WIN32) || defined(USE_STATIC_NANOMSG)
#include "../../crypto777/nanosrc/nn.h"
#include "../../crypto777/nanosrc/bus.h"
#include "../../crypto777/nanosrc/pubsub.h"
#include "../../crypto777/nanosrc/pipeline.h"
#include "../../crypto777/nanosrc/reqrep.h"
#include "../../crypto777/nanosrc/tcp.h"
#include "../../crypto777/nanosrc/pair.h"
#else
#if defined(WIN32) || defined(USE_STATIC_NANOMSG)
	#include "../../crypto777/nanosrc/nn.h"
	#include "../../crypto777/nanosrc/bus.h"
	#include "../../crypto777/nanosrc/pubsub.h"
	#include "../../crypto777/nanosrc/pipeline.h"
	#include "../../crypto777/nanosrc/reqrep.h"
	#include "../../crypto777/nanosrc/tcp.h"
	#include "../../crypto777/nanosrc/pair.h"
#else
	#include "/usr/local/include/nanomsg/nn.h"
	#include "/usr/local/include/nanomsg/bus.h"
	#include "/usr/local/include/nanomsg/pubsub.h"
	#include "/usr/local/include/nanomsg/pipeline.h"
	#include "/usr/local/include/nanomsg/reqrep.h"
	#include "/usr/local/include/nanomsg/tcp.h"
	#include "/usr/local/include/nanomsg/pair.h"
#endif
#endif

#include "LP_nativeDEX.c"

void LP_main(void *ptr)
{
    char *passphrase; double profitmargin; uint16_t port; cJSON *argjson = ptr;
    if ( (passphrase= jstr(argjson,"passphrase")) != 0 )
    {
        profitmargin = jdouble(argjson,"profitmargin");
        LP_profitratio += profitmargin;
        if ( (port= juint(argjson,"rpcport")) < 1000 )
            port = LP_RPCPORT;
        LPinit(port,LP_RPCPORT+10,LP_RPCPORT+20,LP_RPCPORT+30,passphrase,jint(argjson,"client"),jstr(argjson,"userhome"),argjson);
    }
}

int main(int argc, const char * argv[])
{
    char dirname[512],*passphrase; double incr; cJSON *retjson;
    OS_init();
    if ( strstr(argv[0],"btc2kmd") != 0 && argv[1] != 0 )
    {
        uint8_t addrtype,rmd160[20],rmd160b[20]; char coinaddr[64],coinaddr2[64];
        bitcoin_addr2rmd160(0,&addrtype,rmd160,(char *)argv[1]);
        if ( addrtype == 0 )
        {
            bitcoin_address(coinaddr,0,60,rmd160,20);
            bitcoin_addr2rmd160(0,&addrtype,rmd160b,coinaddr);
            bitcoin_address(coinaddr2,0,0,rmd160b,20);
        }
        else if ( addrtype == 60 )
        {
            bitcoin_address(coinaddr,0,0,rmd160,20);
            bitcoin_addr2rmd160(0,&addrtype,rmd160b,coinaddr);
            bitcoin_address(coinaddr2,0,60,rmd160b,20);
        }
        printf("(%s) -> %s -> %s\n",(char *)argv[1],coinaddr,coinaddr2);
        if ( strcmp((char *)argv[1],coinaddr2) != 0 )
            printf("ERROR\n");
        exit(0);
    }
    else if ( argv[1] != 0 && strcmp(argv[1],"hush") == 0 )
    {
        uint32_t timestamp; char str[65],wifstr[128]; bits256 privkey; int32_t i;
        timestamp = (uint32_t)time(NULL);
        //printf("start hush vanitygen t.%u\n",timestamp);
        for (i=0; i<1000000000; i++)
        {
            OS_randombytes(privkey.bytes,sizeof(privkey));
            privkey.bytes[0] = 0x0e;
            privkey.bytes[1] = 0x5b;
            privkey.bytes[2] = 0xf9;
            privkey.bytes[3] = 0xc6;
            privkey.bytes[4] = 0x06;
            privkey.bytes[5] = 0xdd;
            privkey.bytes[6] = 0xbb;
            bitcoin_priv2wiflong(0xab,wifstr,privkey,0x36);
            if ( wifstr[2] == 'x' && wifstr[4] == 'H' && wifstr[5] == 'u' && wifstr[6] == 's' )//&& wifstr[3] == 'x' )
            {
                if ( wifstr[7] == 'h' && wifstr[8] == 'L' && wifstr[9] == 'i' )
                {
                    //printf("i.%d %s -> wif.%s\n",i,bits256_str(str,privkey),wifstr);
                    if ( wifstr[10] == 's' && wifstr[11] == 't' )
                    {
                        printf("{\"iters\":%d,\"privkey\":\"%s\",\"wif\":\"%s\"}\n",i,bits256_str(str,privkey),wifstr);
                        break;
                    }
                }
            } //else printf("failed %s\n",wifstr);
        }
        //printf("done hush vanitygen done %u elapsed %d\n",(uint32_t)time(NULL),(uint32_t)time(NULL) - timestamp);
        exit(0);
    }
    else if ( argv[1] != 0 && strcmp(argv[1],"vanity") == 0 && argv[2] != 0 )
    {
        uint32_t timestamp; uint8_t pubkey33[33]; char str[65],coinaddr[64],wifstr[128]; bits256 privkey; int32_t i,len; void *ctx;
        ctx = bitcoin_ctx();
        len = (int32_t)strlen(argv[2]);
        timestamp = (uint32_t)time(NULL);
        printf("start vanitygen (%s).%d t.%u\n",argv[2],len,timestamp);
        for (i=0; i<1000000000; i++)
        {
            OS_randombytes(privkey.bytes,sizeof(privkey));
            bitcoin_priv2pub(ctx,pubkey33,coinaddr,privkey,0,60);
            if ( strncmp(coinaddr+1,argv[2],len-1) == 0 )
            {
                bitcoin_priv2wif(0,wifstr,privkey,188);
                printf("i.%d %s -> %s wif.%s\n",i,bits256_str(str,privkey),coinaddr,wifstr);
                if ( coinaddr[1+len-1] == argv[2][len-1] )
                    break;
            } //else printf("failed %s\n",wifstr);
        }
        printf("done vanitygen.(%s) done %u elapsed %d\n",argv[2],(uint32_t)time(NULL),(uint32_t)time(NULL) - timestamp);
        exit(0);
    }
    sprintf(dirname,"%s",GLOBAL_DBDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/SWAPS",GLOBAL_DBDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/PRICES",GLOBAL_DBDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/UNSPENTS",GLOBAL_DBDIR), OS_ensure_directory(dirname);
#ifdef FROM_JS
    argc = 2;
    retjson = cJSON_Parse("{\"client\":1,\"passphrase\":\"test\"}");
    printf("calling LP_main(%s)\n",jprint(retjson,0));
    LP_main(retjson);
    emscripten_set_main_loop(LP_fromjs_iter,1,0);
#else
    if ( argc == 1 )
    {
        //LP_privkey_tests();
        LP_NXT_redeems();
        sleep(3);
        return(0);
    }
    if ( argc > 1 && (retjson= cJSON_Parse(argv[1])) != 0 )
    {
        if ( jint(retjson,"docker") == 1 )
            DOCKERFLAG = 1;
        else if ( jstr(retjson,"docker") != 0 )
            DOCKERFLAG = (uint32_t)calc_ipbits(jstr(retjson,"docker"));
        if ( (passphrase= jstr(retjson,"passphrase")) == 0 )
            jaddstr(retjson,"passphrase","test");
        if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)LP_main,(void *)retjson) != 0 )
        {
            printf("error launching LP_main (%s)\n",jprint(retjson,0));
            exit(-1);
        } //else printf("(%s) launched.(%s)\n",argv[1],passphrase);
        incr = 100.;
        while ( (1) )
            sleep(100000);
    }
#endif
    return 0;
}
