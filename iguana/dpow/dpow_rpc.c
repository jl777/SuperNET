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

#define issue_curl(cmdstr) bitcoind_RPC(0,"curl",cmdstr,0,0,0,0)

cJSON *dpow_getinfo(struct supernet_info *myinfo,struct iguana_info *coin)
{
    char buf[128],*retstr=0; cJSON *json = 0;
    if ( coin->FULLNODE < 0 )
    {
        buf[0] = 0;
        retstr = bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"getinfo",buf);
        usleep(10000);
    }
    else if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        retstr = bitcoinrpc_getinfo(myinfo,coin,0,0);
    }
    else
    {
        return(0);
    }
    if ( retstr != 0 )
    {
        json = cJSON_Parse(retstr);
        free(retstr);
        if ( strcmp(coin->symbol,"BTC") == 0 )
        {
            sprintf(buf,"[%d]",2);
            if ( (retstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"estimatefee",buf)) != 0 )
            {
                if ( atof(retstr) > SMALLVAL )
                    jaddnum(json,"estimatefee",atof(retstr));
                free(retstr);
            }
        }
    }
    return(json);
}
const char *Notaries_elected[][2] =
{
    { "0_jl777_testA", "03b7621b44118017a16043f19b30cc8a4cfe068ac4e42417bae16ba460c80f3828" },
    { "0_jl777_testB", "02ebfc784a4ba768aad88d44d1045d240d47b26e248cafaf1c5169a42d7a61d344" },
    { "0_kolo_testA", "0287aa4b73988ba26cf6565d815786caf0d2c4af704d7883d163ee89cd9977edec" },
    { "artik_AR", "029acf1dcd9f5ff9c455f8bb717d4ae0c703e089d16cf8424619c491dff5994c90" },
    { "artik_EU", "03f54b2c24f82632e3cdebe4568ba0acf487a80f8a89779173cdb78f74514847ce" },
    { "artik_NA", "0224e31f93eff0cc30eaf0b2389fbc591085c0e122c4d11862c1729d090106c842" },
    { "artik_SH", "02bdd8840a34486f38305f311c0e2ae73e84046f6e9c3dd3571e32e58339d20937" },
    { "badass_EU", "0209d48554768dd8dada988b98aca23405057ac4b5b46838a9378b95c3e79b9b9e" },
    { "badass_NA", "02afa1a9f948e1634a29dc718d218e9d150c531cfa852843a1643a02184a63c1a7" },
    { "badass_SH", "026b49dd3923b78a592c1b475f208e23698d3f085c4c3b4906a59faf659fd9530b" },
    { "crackers_EU", "03bc819982d3c6feb801ec3b720425b017d9b6ee9a40746b84422cbbf929dc73c3" }, // 10
    { "crackers_NA", "03205049103113d48c7c7af811b4c8f194dafc43a50d5313e61a22900fc1805b45" },
    { "crackers_SH", "02be28310e6312d1dd44651fd96f6a44ccc269a321f907502aae81d246fabdb03e" },
    { "durerus_EU", "02bcbd287670bdca2c31e5d50130adb5dea1b53198f18abeec7211825f47485d57" },
    { "etszombi_AR", "031c79168d15edabf17d9ec99531ea9baa20039d0cdc14d9525863b83341b210e9" },
    { "etszombi_EU", "0281b1ad28d238a2b217e0af123ce020b79e91b9b10ad65a7917216eda6fe64bf7" },
    { "etszombi_SH", "025d7a193c0757f7437fad3431f027e7b5ed6c925b77daba52a8755d24bf682dde" },
    { "farl4web_EU", "0300ecf9121cccf14cf9423e2adb5d98ce0c4e251721fa345dec2e03abeffbab3f" },
    { "farl4web_SH", "0396bb5ed3c57aa1221d7775ae0ff751e4c7dc9be220d0917fa8bbdf670586c030" },
    { "fullmoon_AR", "0254b1d64840ce9ff6bec9dd10e33beb92af5f7cee628f999cb6bc0fea833347cc" },
    { "fullmoon_NA", "031fb362323b06e165231c887836a8faadb96eda88a79ca434e28b3520b47d235b" }, // 20
    { "fullmoon_SH", "030e12b42ec33a80e12e570b6c8274ce664565b5c3da106859e96a7208b93afd0d" },
    { "grewal_NA", "03adc0834c203d172bce814df7c7a5e13dc603105e6b0adabc942d0421aefd2132" },
    { "grewal_SH", "03212a73f5d38a675ee3cdc6e82542a96c38c3d1c79d25a1ed2e42fcf6a8be4e68" },
    { "indenodes_AR", "02ec0fa5a40f47fd4a38ea5c89e375ad0b6ddf4807c99733c9c3dc15fb978ee147" },
    { "indenodes_EU", "0221387ff95c44cb52b86552e3ec118a3c311ca65b75bf807c6c07eaeb1be8303c" },
    { "indenodes_NA", "02698c6f1c9e43b66e82dbb163e8df0e5a2f62f3a7a882ca387d82f86e0b3fa988" },
    { "indenodes_SH", "0334e6e1ec8285c4b85bd6dae67e17d67d1f20e7328efad17ce6fd24ae97cdd65e" },
    { "jeezy_EU", "023cb3e593fb85c5659688528e9a4f1c4c7f19206edc7e517d20f794ba686fd6d6" },
    { "jsgalt_NA", "027b3fb6fede798cd17c30dbfb7baf9332b3f8b1c7c513f443070874c410232446" },
    { "karasugoi_NA", "02a348b03b9c1a8eac1b56f85c402b041c9bce918833f2ea16d13452309052a982" }, // 30
    { "kashifali_EU", "033777c52a0190f261c6f66bd0e2bb299d30f012dcb8bfff384103211edb8bb207" },
    { "kolo_AR", "03016d19344c45341e023b72f9fb6e6152fdcfe105f3b4f50b82a4790ff54e9dc6" },
    { "kolo_SH", "02aa24064500756d9b0959b44d5325f2391d8e95c6127e109184937152c384e185" },
    { "metaphilibert_AR", "02adad675fae12b25fdd0f57250b0caf7f795c43f346153a31fe3e72e7db1d6ac6" },
    { "movecrypto_AR", "022783d94518e4dc77cbdf1a97915b29f427d7bc15ea867900a76665d3112be6f3" },
    { "movecrypto_EU", "021ab53bc6cf2c46b8a5456759f9d608966eff87384c2b52c0ac4cc8dd51e9cc42" },
    { "movecrypto_NA", "02efb12f4d78f44b0542d1c60146738e4d5506d27ec98a469142c5c84b29de0a80" },
    { "movecrypto_SH", "031f9739a3ebd6037a967ce1582cde66e79ea9a0551c54731c59c6b80f635bc859" },
    { "muros_AR", "022d77402fd7179335da39479c829be73428b0ef33fb360a4de6890f37c2aa005e" },
    { "noashh_AR", "029d93ef78197dc93892d2a30e5a54865f41e0ca3ab7eb8e3dcbc59c8756b6e355" }, // 40
    { "noashh_EU", "02061c6278b91fd4ac5cab4401100ffa3b2d5a277e8f71db23401cc071b3665546" },
    { "noashh_NA", "033c073366152b6b01535e15dd966a3a8039169584d06e27d92a69889b720d44e1" },
    { "nxtswe_EU", "032fb104e5eaa704a38a52c126af8f67e870d70f82977e5b2f093d5c1c21ae5899" },
    { "polycryptoblog_NA", "02708dcda7c45fb54b78469673c2587bfdd126e381654819c4c23df0e00b679622" },
    { "pondsea_AR", "032e1c213787312099158f2d74a89e8240a991d162d4ce8017d8504d1d7004f735" },
    { "pondsea_EU", "0225aa6f6f19e543180b31153d9e6d55d41bc7ec2ba191fd29f19a2f973544e29d" },
    { "pondsea_NA", "031bcfdbb62268e2ff8dfffeb9ddff7fe95fca46778c77eebff9c3829dfa1bb411" },
    { "pondsea_SH", "02209073bc0943451498de57f802650311b1f12aa6deffcd893da198a544c04f36" },
    { "popcornbag_AR", "02761f106fb34fbfc5ddcc0c0aa831ed98e462a908550b280a1f7bd32c060c6fa3" },
    { "popcornbag_NA", "03c6085c7fdfff70988fda9b197371f1caf8397f1729a844790e421ee07b3a93e8" }, // 50
    { "ptytrader_NA", "0328c61467148b207400b23875234f8a825cce65b9c4c9b664f47410b8b8e3c222" },
    { "ptytrader_SH", "0250c93c492d8d5a6b565b90c22bee07c2d8701d6118c6267e99a4efd3c7748fa4" },
    { "rnr_AR", "029bdb08f931c0e98c2c4ba4ef45c8e33a34168cb2e6bf953cef335c359d77bfcd" },
    { "rnr_EU", "03f5c08dadffa0ffcafb8dd7ffc38c22887bd02702a6c9ac3440deddcf2837692b" },
    { "rnr_NA", "02e17c5f8c3c80f584ed343b8dcfa6d710dfef0889ec1e7728ce45ce559347c58c" },
    { "rnr_SH", "037536fb9bdfed10251f71543fb42679e7c52308bcd12146b2568b9a818d8b8377" },
    { "titomane_AR", "03cda6ca5c2d02db201488a54a548dbfc10533bdc275d5ea11928e8d6ab33c2185" },
    { "titomane_EU", "02e41feded94f0cc59f55f82f3c2c005d41da024e9a805b41105207ef89aa4bfbd" },
    { "titomane_SH", "035f49d7a308dd9a209e894321f010d21b7793461b0c89d6d9231a3fe5f68d9960" },
    { "vanbreuk_EU", "024f3cad7601d2399c131fd070e797d9cd8533868685ddbe515daa53c2e26004c3" }, // 60
    { "xrobesx_NA", "03f0cc6d142d14a40937f12dbd99dbd9021328f45759e26f1877f2a838876709e1" },
    { "xxspot1_XX", "02ef445a392fcaf3ad4176a5da7f43580e8056594e003eba6559a713711a27f955" },
    { "xxspot2_XX", "03d85b221ea72ebcd25373e7961f4983d12add66a92f899deaf07bab1d8b6f5573" }
};

int32_t komodo_notaries(char *symbol,uint8_t pubkeys[64][33],int32_t height)
{
    int32_t i,num=-1; struct iguana_info *coin; char params[256],*retstr,*pubkeystr; cJSON *retjson,*item,*array;
    if ( (coin= iguana_coinfind(symbol)) != 0 )
    {
        if ( height < 0 )
        {
            if ( (retjson= dpow_getinfo(SuperNET_MYINFO(0),coin)) != 0 )
            {
                height = jint(retjson,"blocks") - 1;
                free_json(retjson);
//printf("komodo_notaries height.%d\n",height);
            }
        }
        if ( height >= 180000 )
        {
            for (i=0; i<sizeof(Notaries_elected)/sizeof(*Notaries_elected); i++)
                decode_hex(pubkeys[i],33,(char *)Notaries_elected[i][1]);
            return(i);
        }
        if ( coin->FULLNODE < 0 )
        {
            sprintf(params,"[\"%d\"]",height);
            if ( (retstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"notaries",params)) != 0 )
            {
                if ( (retjson= cJSON_Parse(retstr)) != 0 )
                {
//printf("%s\n",retstr);
                    if ( (array= jarray(&num,retjson,"notaries")) != 0 )
                    {
                        if ( num > 64 )
                        {
                            printf("warning: numnotaries.%d? > 64?\n",num);
                            num = 64;
                        }
                        for (i=0; i<num; i++)
                        {
                            item = jitem(array,i);
                            if ( (pubkeystr= jstr(item,"pubkey")) != 0 && strlen(pubkeystr) == 66 )
                                decode_hex(pubkeys[i],33,pubkeystr);
                            else printf("error i.%d of %d (%s)\n",i,num,pubkeystr!=0?pubkeystr:"");
                        }
                        //printf("notaries.[%d] <- ht.%d\n",num,height);
                    }
                    free_json(retjson);
                }
                free(retstr);
            }
        }
    }
    //printf("komodo_notaries returns.%d\n",num);
    return(num);
}

bits256 dpow_getbestblockhash(struct supernet_info *myinfo,struct iguana_info *coin)
{
    char *retstr; bits256 blockhash;
    memset(blockhash.bytes,0,sizeof(blockhash));
    if ( coin->FULLNODE < 0 )
    {
        if ( coin->lastbesthashtime+2 > time(NULL) && bits256_nonz(coin->lastbesthash) != 0 )
            return(coin->lastbesthash);
        if ( (retstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"getbestblockhash","")) != 0 )
        {
            if ( 0 && strcmp(coin->symbol,"USD") == 0 )
                printf("%s getbestblockhash.(%s)\n",coin->symbol,retstr);
            if ( is_hexstr(retstr,0) == sizeof(blockhash)*2 )
                decode_hex(blockhash.bytes,sizeof(blockhash),retstr);
            free(retstr);
        }
    }
    else if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        blockhash = coin->blocks.hwmchain.RO.hash2;
    }
    else
    {
        
    }
    if ( bits256_nonz(blockhash) != 0 )
    {
        coin->lastbesthash = blockhash;
        coin->lastbesthashtime = (uint32_t)time(NULL);
    }
    return(blockhash);
}

int32_t dpow_paxpending(uint8_t *hex,uint32_t *paxwdcrcp)
{
    struct iguana_info *coin; char *retstr,*hexstr; cJSON *retjson; int32_t n=0; uint32_t paxwdcrc;
    paxwdcrc = 0;
    if ( (coin= iguana_coinfind("KMD")) != 0 )
    {
        if ( coin->FULLNODE < 0 )
        {
            if ( (retstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"paxpending","")) != 0 )
            {
                if ( (retjson= cJSON_Parse(retstr)) != 0 )
                {
                    if ( (hexstr= jstr(retjson,"withdraws")) != 0 && (n= is_hexstr(hexstr,0)) > 1 )
                    {
                        n >>= 1;
                        //printf("PAXPENDING.(%s)\n",hexstr);
                        decode_hex(hex,n,hexstr);
                        paxwdcrc = calc_crc32(0,hex,n) & 0xffffff00;
                        paxwdcrc |= (n & 0xff);
                    }
                    free_json(retjson);
                } else printf("dpow_paxpending: parse error.(%s)\n",retstr);
                free(retstr);
            } else printf("dpow_paxpending: paxwithdraw null return\n");
        } else printf("dpow_paxpending: KMD FULLNODE.%d\n",coin->FULLNODE);
    } else printf("dpow_paxpending: cant find KMD\n");
    if ( *paxwdcrcp != paxwdcrc )
        *paxwdcrcp = paxwdcrc;
    return(n);
}

bits256 dpow_getblockhash(struct supernet_info *myinfo,struct iguana_info *coin,int32_t height)
{
    char buf[128],*retstr=0; bits256 blockhash;
    memset(blockhash.bytes,0,sizeof(blockhash));
    if ( coin->FULLNODE < 0 )
    {
        sprintf(buf,"%d",height);
        retstr = bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"getblockhash",buf);
        //printf("%s ht.%d -> getblockhash.(%s)\n",coin->symbol,height,retstr);
        usleep(10000);
    }
    else if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        printf("test iguana mode getblockhash\n");
        retstr = bitcoinrpc_getblockhash(myinfo,coin,0,0,height);
    }
    else
    {
        return(blockhash);
    }
    if ( retstr != 0 )
    {
        if ( strlen(retstr) == 64 )
            decode_hex(blockhash.bytes,32,retstr);
        free(retstr);
    }
    return(blockhash);
}

cJSON *dpow_getblock(struct supernet_info *myinfo,struct iguana_info *coin,bits256 blockhash)
{
    char buf[128],str[65],*retstr=0; cJSON *json = 0;
    if ( coin->FULLNODE < 0 )
    {
        sprintf(buf,"\"%s\"",bits256_str(str,blockhash));
        retstr = bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"getblock",buf);
        if ( 0 && strcmp(coin->symbol,"USD") == 0 )
            printf("%s getblock.(%s)\n",coin->symbol,retstr);
        usleep(10000);
    }
    else if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        retstr = bitcoinrpc_getblock(myinfo,coin,0,0,blockhash,1,0);
    }
    else
    {
        return(0);
    }
    if ( retstr != 0 )
    {
        json = cJSON_Parse(retstr);
        free(retstr);
    }
    return(json);
}

char *dpow_validateaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *address)
{
    char buf[128],*retstr=0; 
    if ( coin->FULLNODE < 0 )
    {
        sprintf(buf,"\"%s\"",address);
        retstr = bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"validateaddress",buf);
        usleep(10000);
    }
    else if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        retstr = bitcoinrpc_validateaddress(myinfo,coin,0,0,address);
    }
    else
    {
        return(0);
    }
    return(retstr);
}

cJSON *dpow_gettxout(struct supernet_info *myinfo,struct iguana_info *coin,bits256 txid,int32_t vout)
{
    char buf[128],str[65],*retstr=0; cJSON *json = 0;
    sprintf(buf,"\"%s\", %d",bits256_str(str,txid),vout);
    if ( coin->FULLNODE < 0 )
    {
        retstr = bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"gettxout",buf);
        usleep(10000);
    }
    else if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        printf("need to test following call\n");
        retstr = bitcoinrpc_gettxout(myinfo,coin,0,buf,txid,1,0); // untested
    }
    else
    {
        return(0);
    }
    if ( retstr != 0 )
    {
        json = cJSON_Parse(retstr);
        free(retstr);
    }
    //printf("dpow_gettxout.(%s)\n",retstr);
    return(json);
}

char *dpow_decoderawtransaction(struct supernet_info *myinfo,struct iguana_info *coin,char *rawtx)
{
    char *retstr,*paramstr; cJSON *array;
    if ( coin->FULLNODE < 0 )
    {
        array = cJSON_CreateArray();
        jaddistr(array,rawtx);
        paramstr = jprint(array,1);
        retstr = bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"decoderawtransaction",paramstr);
        //printf("%s decoderawtransaction.(%s) <- (%s)\n",coin->symbol,retstr,paramstr);
        free(paramstr);
        usleep(10000);
    }
    else if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        retstr = bitcoinrpc_decoderawtransaction(myinfo,coin,0,0,rawtx,1);
    }
    else
    {
        return(0);
    }
    return(retstr);
}

cJSON *dpow_gettransaction(struct supernet_info *myinfo,struct iguana_info *coin,bits256 txid)
{
    char buf[128],str[65],*retstr=0; cJSON *json = 0;
    if ( coin->FULLNODE < 0 )
    {
        sprintf(buf,"[\"%s\", 1]",bits256_str(str,txid));
        if ( (retstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"getrawtransaction",buf)) != 0 )
        {
        }
        usleep(10000);
    }
    else if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        retstr = bitcoinrpc_getrawtransaction(myinfo,coin,0,0,txid,1);
    }
    else
    {
        return(0);
    }
    if ( retstr != 0 )
    {
        json = cJSON_Parse(retstr);
        free(retstr);
    }
    return(json);
}

cJSON *dpow_listunspent(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr)
{
    char buf[128],*retstr; cJSON *array,*json = 0;
    if ( coin->FULLNODE < 0 )
    {
        sprintf(buf,"1, 99999999, [\"%s\"]",coinaddr);
        if ( (retstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"listunspent",buf)) != 0 )
        {
            json = cJSON_Parse(retstr);
            //printf("%s (%s) listunspent.(%s)\n",coin->symbol,buf,retstr);
            free(retstr);
        } else printf("%s null retstr from (%s)n",coin->symbol,buf);
    }
    else if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        array = cJSON_CreateArray();
        jaddistr(array,coinaddr);
        json = iguana_listunspents(myinfo,coin,array,1,coin->longestchain,"");
        free_json(array);
    }
    else
    {
        return(0);
    }
    return(json);
}

cJSON *dpow_listspent(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr)
{
    if ( myinfo->DEXEXPLORER != 0 )
        return(kmd_listspent(myinfo,coin,coinaddr));
    else
    {
        return(0);
    }
}

cJSON *dpow_getbalance(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr)
{
    if ( myinfo->DEXEXPLORER != 0 )
        return(kmd_getbalance(myinfo,coin,coinaddr));
    else
    {
        return(0);
    }
}

cJSON *dpow_gettxin(struct supernet_info *myinfo,struct iguana_info *coin,bits256 txid,int32_t vout)
{
    if ( myinfo->DEXEXPLORER != 0 )
        return(kmd_gettxin(coin,txid,vout));
    else
    {
        return(0);
    }
}

cJSON *dpow_listtransactions(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr,int32_t count,int32_t skip)
{
    char buf[128],*retstr; cJSON *json = 0;
    if ( coin->FULLNODE < 0 )
    {
        if ( count == 0 )
            count = 100;
        sprintf(buf,"[\"%s\", %d, %d, true]",coinaddr,count,skip);
        if ( (retstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"listtransactions",buf)) != 0 )
        {
            //printf("LIST.(%s)\n",retstr);
            json = cJSON_Parse(retstr);
            free(retstr);
            return(json);
        } else printf("%s null retstr from (%s)n",coin->symbol,buf);
    }
    return(0);
}

char *dpow_signrawtransaction(struct supernet_info *myinfo,struct iguana_info *coin,char *rawtx,cJSON *vins)
{
    cJSON *array,*privkeys,*item; char *wifstr,*str,*paramstr,*retstr; uint8_t script[256]; int32_t i,n,len,hashtype; struct vin_info V; struct iguana_waddress *waddr; struct iguana_waccount *wacct;
    if ( coin->FULLNODE < 0 )
    {
        array = cJSON_CreateArray();
        jaddistr(array,rawtx);
        jaddi(array,jduplicate(vins));
        paramstr = jprint(array,1);
        //printf("signrawtransaction\n");
        retstr = bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"signrawtransaction",paramstr);
        //printf("%s signrawtransaction.(%s) params.(%s)\n",coin->symbol,retstr,paramstr);
        free(paramstr);
        usleep(10000);
        return(retstr);
    }
    else if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        privkeys = cJSON_CreateArray();
        if ( (n= cJSON_GetArraySize(vins)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                wifstr = "";
                item = jitem(vins,i);
                if ( (str= jstr(item,"scriptPubkey")) != 0 && is_hexstr(str,0) > 0 && strlen(str) < sizeof(script)*2 )
                {
                    len = (int32_t)strlen(str) >> 1;
                    decode_hex(script,len,str);
                    V.spendlen = len;
                    memcpy(V.spendscript,script,len);
                    if ( (hashtype= _iguana_calcrmd160(coin,&V)) >= 0 && V.coinaddr[0] != 0 )
                    {
                        if ( (waddr= iguana_waddresssearch(myinfo,&wacct,V.coinaddr)) != 0 )
                        {
                            if ( bits256_nonz(waddr->privkey) != 0 )
                            {
                                if ( bitcoin_priv2wif(waddr->wifstr,waddr->privkey,coin->chain->wiftype) > 0 )
                                {
                                    wifstr = waddr->wifstr;
                                }
                            }
                        }
                    }
                }
                jaddistr(privkeys,wifstr);
            }
        }
        retstr = bitcoinrpc_signrawtransaction(myinfo,coin,0,0,rawtx,vins,privkeys,"ALL");
        printf("call sign.(%s) vins.(%s) privs.(%s) -> (%s)\n",rawtx,jprint(vins,0),jprint(privkeys,0),retstr);
        free_json(privkeys);
        return(retstr);
    }
    else
    {
        return(0);
    }
}

cJSON *dpow_kvupdate(struct supernet_info *myinfo,struct iguana_info *coin,char *key,char *value,int32_t flags)
{
    char params[IGUANA_MAXSCRIPTSIZE+256],*retstr; cJSON *retjson;
    if ( coin->FULLNODE < 0 )
    {
        sprintf(params,"[\"%s\", \"%s\", \"%d\"]",key,value,flags);
        //printf("KVUPDATE.%s\n",params);
        retstr = bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"kvupdate",params);
        if ( (retjson= cJSON_Parse(retstr)) == 0 )
        {
            free(retstr);
            return(cJSON_Parse("{\"error\":\"couldnt parse kvupdate return\"}"));
        }
        free(retstr);
        return(retjson);
    } else return(cJSON_Parse("{\"error\":\"only native komodod supports KV\"}"));
}

cJSON *dpow_kvsearch(struct supernet_info *myinfo,struct iguana_info *coin,char *key)
{
    char params[IGUANA_MAXSCRIPTSIZE+256],*retstr; cJSON *retjson;
    if ( coin->FULLNODE < 0 )
    {
        sprintf(params,"[\"%s\"]",key);
        retstr = bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"kvsearch",params);
        if ( (retjson= cJSON_Parse(retstr)) == 0 )
        {
            free(retstr);
            return(cJSON_Parse("{\"error\":\"couldnt parse kvupdate return\"}"));
        }
        free(retstr);
        return(retjson);
    } else return(cJSON_Parse("{\"error\":\"only native komodod supports KV\"}"));
}


char *dpow_sendrawtransaction(struct supernet_info *myinfo,struct iguana_info *coin,char *signedtx)
{
    bits256 txid; cJSON *json,*array; char *paramstr,*retstr;
    if ( coin->FULLNODE < 0 )
    {
        array = cJSON_CreateArray();
        jaddistr(array,signedtx);
        paramstr = jprint(array,1);
        retstr = bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"sendrawtransaction",paramstr);
        printf(">>>>>>>>>>> %s dpow_sendrawtransaction.(%s) -> (%s)\n",coin->symbol,paramstr,retstr);
        free(paramstr);
        return(retstr);
    }
    else if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        txid = iguana_sendrawtransaction(myinfo,coin,signedtx);
        json = cJSON_CreateObject();
        jaddbits256(json,"result",txid);
        return(jprint(json,1));
    }
    else
    {
        return(0);
    }
}

char *dpow_alladdresses(struct supernet_info *myinfo,struct iguana_info *coin)
{
    char *retstr,fname[1024]; long filesize;
    sprintf(fname,"%s/alladdresses.%s",GLOBAL_CONFSDIR,coin->symbol), OS_compatible_path(fname);
    retstr = OS_filestr(&filesize,fname);
    return(retstr);
}

void update_alladdresses(struct supernet_info *myinfo,struct iguana_info *coin,char *address)
{
    struct hashstr_item *hashstr,*tmp; cJSON *alljson; char *outstr,*instr,fname[1024]; int32_t i,n,saveflag = 0;
    HASH_FIND(hh,coin->alladdresses,address,strlen(address),hashstr);
    if ( hashstr == 0 )
    {
        hashstr = calloc(1,sizeof(*hashstr));
        strncpy(hashstr->address,address,sizeof(hashstr->address));
        HASH_ADD_KEYPTR(hh,coin->alladdresses,hashstr->address,strlen(address),hashstr);
        saveflag = 1;
    }
    if ( saveflag != 0 )
    {
        FILE *fp;
        if ( (instr= dpow_alladdresses(myinfo,coin)) != 0 )
        {
            if ( (alljson= cJSON_Parse(instr)) != 0 )
            {
                n = cJSON_GetArraySize(alljson);
                for (i=0; i<n; i++)
                {
                    address = jstri(alljson,i);
                    HASH_FIND(hh,coin->alladdresses,address,strlen(address),hashstr);
                    if ( hashstr == 0 )
                    {
                        hashstr = calloc(1,sizeof(*hashstr));
                        strncpy(hashstr->address,address,sizeof(hashstr->address));
                        HASH_ADD_KEYPTR(hh,coin->alladdresses,hashstr->address,strlen(address),hashstr);
                    }
                }
                free_json(alljson);
            }
            free(instr);
        }
        alljson = cJSON_CreateArray();
        HASH_ITER(hh,coin->alladdresses,hashstr,tmp)
        {
            jaddistr(alljson,hashstr->address);
        }
        outstr = jprint(alljson,0);
        sprintf(fname,"%s/alladdresses.%s",GLOBAL_CONFSDIR,coin->symbol), OS_compatible_path(fname);
        if ( (fp= fopen(fname,"wb")) != 0 )
        {
            fwrite(outstr,1,strlen(outstr)+1,fp);
            fclose(fp);
            printf("importaddress.(%s) -> alladdresses.%s\n",address,coin->symbol);
        }
        free(outstr);
    }
}

cJSON *dpow_checkaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *address)
{
    int32_t isvalid=0,doneflag=0; char *retstr; cJSON *validatejson,*retjson = cJSON_CreateObject();
    if ( (retstr= dpow_validateaddress(myinfo,coin,address)) != 0 )
    {
        if ( (validatejson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (isvalid= is_cJSON_True(jobj(validatejson,"isvalid")) != 0) != 0 )
            {
                if ( is_cJSON_True(jobj(validatejson,"iswatchonly")) != 0 || is_cJSON_True(jobj(validatejson,"ismine")) != 0 )
                    doneflag = 1;
            }
            free_json(validatejson);
        }
        free(retstr);
        retstr = 0;
    }
    if ( isvalid == 0 )
        jaddstr(retjson,"error","invalid address");
    else if ( doneflag != 0 )
    {
        jaddstr(retjson,"coin",coin->symbol);
        jaddstr(retjson,"address",address);
    }
    return(retjson);
}

char *dpow_importaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *address)
{
    char buf[1024],*retstr; cJSON *validatejson; int32_t isvalid=0,doneflag = 0;
    if ( (retstr= dpow_validateaddress(myinfo,coin,address)) != 0 )
    {
        if ( (validatejson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (isvalid= is_cJSON_True(jobj(validatejson,"isvalid")) != 0) != 0 )
            {
                if ( is_cJSON_True(jobj(validatejson,"iswatchonly")) != 0 || is_cJSON_True(jobj(validatejson,"ismine")) != 0 )
                    doneflag = 1;
            }
            free_json(validatejson);
        }
        free(retstr);
        retstr = 0;
    }
    if ( isvalid == 0 )
        return(clonestr("{\"isvalid\":false}"));
    update_alladdresses(myinfo,coin,address);
    if ( doneflag != 0 )
        return(0); // success
    if ( coin->FULLNODE < 0 )
    {
        sprintf(buf,"[\"%s\", \"%s\", false]",address,address);
        retstr = bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"importaddress",buf);
        printf("%s importaddress.(%s) -> (%s)\n",coin->symbol,address,retstr);
        return(retstr);
    }
    else return(0);
}

void init_alladdresses(struct supernet_info *myinfo,struct iguana_info *coin)
{
    char *alladdresses,*retstr; cJSON *alljson; int32_t i,n;
    if ( (alladdresses= dpow_alladdresses(myinfo,coin)) != 0 )
    {
        printf("(%s) ALL.(%s)\n",coin->symbol,alladdresses);
        if ( (alljson= cJSON_Parse(alladdresses)) != 0 )
        {
            if ( is_cJSON_Array(alljson) != 0 && (n= cJSON_GetArraySize(alljson)) > 0 )
            {
                for (i=0; i<n; i++)
                    if ( (retstr= dpow_importaddress(myinfo,coin,jstri(alljson,i))) != 0 )
                        free(retstr);
            }
            free_json(alljson);
        }
        free(alladdresses);
    }
}

int32_t dpow_getchaintip(struct supernet_info *myinfo,bits256 *blockhashp,uint32_t *blocktimep,bits256 *txs,uint32_t *numtxp,struct iguana_info *coin)
{
    int32_t n,i,height = -1,maxtx = *numtxp; bits256 besthash,oldhash; cJSON *array,*json;
    *numtxp = *blocktimep = 0;
    oldhash = coin->lastbesthash;
    *blockhashp = besthash = dpow_getbestblockhash(myinfo,coin);
    if ( bits256_nonz(besthash) != 0 && bits256_cmp(oldhash,besthash) != 0 )
    {
        if ( (json= dpow_getblock(myinfo,coin,besthash)) != 0 )
        {
            if ( (height= juint(json,"height")) != 0 && (*blocktimep= juint(json,"time")) != 0 )
            {
                coin->lastbestheight = height;
                if ( height > coin->longestchain )
                    coin->longestchain = height;
                if ( txs != 0 && numtxp != 0 && (array= jarray(&n,json,"tx")) != 0 )
                {
                    for (i=0; i<n&&i<maxtx; i++)
                        txs[i] = jbits256i(array,i);
                    if ( 0 && strcmp(coin->symbol,"USD") == 0 )
                        printf("dpow_getchaintip %s ht.%d time.%u numtx.%d\n",coin->symbol,height,*blocktimep,n);
                    *numtxp = n;
                }
            } else height = -1;
            free_json(json);
        }
    }
    return(coin->lastbestheight);
}

int32_t dpow_vini_ismine(struct supernet_info *myinfo,struct dpow_info *dp,cJSON *item)
{
    cJSON *sobj; char *hexstr; int32_t len; uint8_t data[35];
    if ( (sobj= jobj(item,"scriptPubKey")) != 0 && (hexstr= jstr(sobj,"hex")) != 0 )
    {
        len = (int32_t)strlen(hexstr) >> 1;
        if ( len <= sizeof(data) )
        {
            decode_hex(data,len,hexstr);
            if ( len == 35 && data[34] == CHECKSIG && data[0] == 33 && memcmp(data+1,dp->minerkey33,33) == 0 )
                return(0);
        }
    }
    return(-1);
}

int32_t dpow_haveutxo(struct supernet_info *myinfo,struct iguana_info *coin,bits256 *txidp,int32_t *voutp,char *coinaddr)
{
    int32_t vout,haveutxo = 0; uint32_t i,j,n,r; bits256 txid; cJSON *unspents,*item; uint64_t satoshis; char *str,*address; uint8_t script[35];
    memset(txidp,0,sizeof(*txidp));
    *voutp = -1;
    if ( (unspents= dpow_listunspent(myinfo,coin,coinaddr)) != 0 )
    {
        if ( (n= cJSON_GetArraySize(unspents)) > 0 )
        {
            /*{
             "txid" : "34bc21b40d6baf38e2db5be5353dd0bcc9fe416485a2a68753541ed2f9c194b1",
             "vout" : 0,
             "address" : "RFBmvBaRybj9io1UpgWM4pzgufc3E4yza7",
             "scriptPubKey" : "21039a3f7373ae91588b9edd76a9088b2871f62f3438d172b9f18e0581f64887404aac",
             "amount" : 3.00000000,
             "confirmations" : 4282,
             "spendable" : true
             },*/
            //r = 0;
            //memcpy(&r,coin->symbol,3);
            //r = calc_crc32(0,(void *)&r,sizeof(r));
            OS_randombytes((uint8_t *)&r,sizeof(r));
            for (j=0; j<n; j++)
            {
                i = (r + j) % n;
                if ( (item= jitem(unspents,i)) == 0 )
                    continue;
                if ( is_cJSON_False(jobj(item,"spendable")) != 0 )
                    continue;
                if ( (satoshis= SATOSHIDEN * jdouble(item,"amount")) == 0 )
                    satoshis= SATOSHIDEN * jdouble(item,"value");
                if ( satoshis == DPOW_UTXOSIZE && (address= jstr(item,"address")) != 0 && strcmp(address,coinaddr) == 0 )
                {
                    if ( (str= jstr(item,"scriptPubKey")) != 0 && is_hexstr(str,0) == sizeof(script)*2 )
                    {
                        txid = jbits256(item,"txid");
                        vout = jint(item,"vout");
                        if ( bits256_nonz(txid) != 0 && vout >= 0 )
                        {
                            if ( *voutp < 0 || (rand() % (n/2+1)) == 0 )
                            {
                                *voutp = vout;
                                *txidp = txid;
                            }
                            haveutxo++;
                        }
                    }
                }
            }
            if ( haveutxo == 0 )
                printf("no %s utxo: need to fund address.(%s) or wait for splitfund to confirm\n",coin->symbol,coinaddr);
        } //else printf("null utxo array size\n");
        free_json(unspents);
    } else printf("null return from dpow_listunspent\n");
    if ( 0 && haveutxo > 0 )
        printf("%s haveutxo.%d\n",coin->symbol,haveutxo);
    return(haveutxo);
}

char *dpow_issuemethod(char *userpass,char *method,char *params,uint16_t port)
{
    char url[512],*retstr=0,*retstr2=0,postdata[8192];
    if ( params == 0 || params[0] == 0 )
        params = (char *)"[]";
    if ( strlen(params) < sizeof(postdata)-128 )
    {
        sprintf(url,(char *)"http://127.0.0.1:%u",port);
        sprintf(postdata,"{\"method\":\"%s\",\"params\":%s}",method,params);
        //printf("postdata.(%s) USERPASS.(%s)\n",postdata,KMDUSERPASS);
        retstr2 = bitcoind_RPC(&retstr,(char *)"debug",url,userpass,method,params,0);
    }
    return(retstr2);
}

uint64_t dpow_paxprice(uint64_t *seedp,int32_t height,char *base,char *rel,uint64_t basevolume)
{
    char params[512],*retstr; uint64_t satoshis = 0; cJSON *retjson,*result; struct iguana_info *kmdcoin;
    kmdcoin = iguana_coinfind("KMD");
    *seedp = 0;
    sprintf(params,"[\"%s\", \"%s\", \"%d\", \"%.8f\"]",base,rel,height,(double)basevolume/SATOSHIDEN);
    if ( kmdcoin != 0 && (retstr= dpow_issuemethod(kmdcoin->chain->userpass,"paxprice",params,kmdcoin->chain->rpcport)) != 0 )
    {
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (result= jobj(retjson,"result")) != 0 )
            {
                satoshis = jdouble(result,"relvolume") * SATOSHIDEN;
                *seedp = j64bits(result,"seed");
            }
            free_json(retjson);
        }
        //printf("dpow_paxprice.(%s) -> %s %.8f\n",params,retstr,dstr(satoshis));
    }
    return(satoshis);
}

#define KOMODO_PUBTYPE 60

int32_t PAX_pubkey(int32_t rwflag,uint8_t *pubkey33,uint8_t *addrtypep,uint8_t rmd160[20],char fiat[4],uint8_t *shortflagp,int64_t *fiatoshisp)
{
    if ( rwflag != 0 )
    {
        memset(pubkey33,0,33);
        pubkey33[0] = 0x02 | (*shortflagp != 0);
        memcpy(&pubkey33[1],fiat,3);
        iguana_rwnum(rwflag,&pubkey33[4],sizeof(*fiatoshisp),(void *)fiatoshisp);
        pubkey33[12] = *addrtypep;
        memcpy(&pubkey33[13],rmd160,20);
    }
    else
    {
        *shortflagp = (pubkey33[0] == 0x03);
        memcpy(fiat,&pubkey33[1],3);
        fiat[3] = 0;
        iguana_rwnum(rwflag,&pubkey33[4],sizeof(*fiatoshisp),(void *)fiatoshisp);
        if ( *shortflagp != 0 )
            *fiatoshisp = -(*fiatoshisp);
        *addrtypep = pubkey33[12];
        memcpy(rmd160,&pubkey33[13],20);
    }
    return(33);
}

uint64_t PAX_fiatdest(uint64_t *seedp,int32_t tokomodo,char *destaddr,uint8_t pubkey33[33],char *coinaddr,int32_t kmdheight,char *origbase,int64_t fiatoshis)
{
    uint8_t shortflag=0; char base[4]; int32_t i; uint8_t addrtype,rmd160[20]; int64_t komodoshis=0;
    for (i=0; i<3; i++)
        base[i] = toupper((int32_t)origbase[i]);
    base[i] = 0;
    if ( strcmp(base,"KMD") == 0 )
        return(0);
    if ( fiatoshis < 0 )
        shortflag = 1, fiatoshis = -fiatoshis;
    komodoshis = dpow_paxprice(seedp,kmdheight,base,(char *)"KMD",(uint64_t)fiatoshis);
    if ( bitcoin_addr2rmd160(&addrtype,rmd160,coinaddr) == 20 )
    {
        PAX_pubkey(1,pubkey33,&addrtype,rmd160,base,&shortflag,tokomodo != 0 ? &komodoshis : &fiatoshis);
        bitcoin_address(destaddr,KOMODO_PUBTYPE,pubkey33,33);
    }
    return(komodoshis);
}

int32_t dpow_scriptitemlen(int32_t *opretlenp,uint8_t *script)
{
    int32_t opretlen,len = 0;
    if ( (opretlen= script[len++]) >= 0x4c )
    {
        if ( opretlen == 0x4c )
            opretlen = script[len++];
        else if ( opretlen == 0x4d )
        {
            opretlen = script[len++];
            opretlen = (opretlen << 8) | script[len++];
        }
    }
    *opretlenp = opretlen;
    return(len);
}

cJSON *dpow_paxjson(struct pax_transaction *pax)
{
    uint8_t addrtype,rmd160[20]; int32_t i; char rmdstr[41]; cJSON *item = cJSON_CreateObject();
    if ( pax != 0 )
    {
        jaddbits256(item,"prev_hash",pax->txid);
        jaddnum(item,"prev_vout",pax->vout);
        if ( pax->shortflag != 0 )
            jaddnum(item,"short",pax->shortflag);
        jaddnum(item,pax->symbol,dstr(pax->fiatoshis));
        jaddstr(item,"fiat",pax->symbol);
        jaddnum(item,"kmdheight",pax->kmdheight);
        jaddnum(item,"height",pax->height);
        jaddnum(item,"KMD",dstr(pax->komodoshis));
        jaddstr(item,"address",pax->coinaddr);
        bitcoin_addr2rmd160(&addrtype,rmd160,pax->coinaddr);
        for (i=0; i<20; i++)
            sprintf(&rmdstr[i<<1],"%02x",rmd160[i]);
        rmdstr[40] = 0;
        jaddstr(item,"rmd160",rmdstr);
    }
    return(item);
}

uint64_t dpow_paxtotal(struct dpow_info *dp)
{
    struct pax_transaction *pax,*tmp; uint64_t total = 0;
    pthread_mutex_lock(&dp->paxmutex);
    /*if ( dp->PAX != 0 )
    {
        tmp = 0;
        pax= dp->PAX->hh.next;
        while ( pax != 0 && pax != tmp )
        {
            if ( pax->marked == 0 )
                total += pax->komodoshis;
            tmp = pax;
            pax = pax->hh.next;
        }
    }*/
    HASH_ITER(hh,dp->PAX,pax,tmp)
    {
        if ( pax->marked == 0 )
            total += pax->komodoshis;
    }
    pthread_mutex_unlock(&dp->paxmutex);
    return(total);
}

struct pax_transaction *dpow_paxfind(struct dpow_info *dp,struct pax_transaction *space,bits256 txid,uint16_t vout)
{
    struct pax_transaction *pax;
    pthread_mutex_lock(&dp->paxmutex);
    HASH_FIND(hh,dp->PAX,&txid,sizeof(txid),pax);
    if ( pax != 0 )
        memcpy(space,pax,sizeof(*pax));
    pthread_mutex_unlock(&dp->paxmutex);
    return(pax);
}

struct pax_transaction *dpow_paxmark(struct dpow_info *dp,struct pax_transaction *space,bits256 txid,uint16_t vout,int32_t mark)
{
    struct pax_transaction *pax;
    pthread_mutex_lock(&dp->paxmutex);
    HASH_FIND(hh,dp->PAX,&txid,sizeof(txid),pax);
    if ( pax == 0 )
    {
        pax = (struct pax_transaction *)calloc(1,sizeof(*pax));
        pax->txid = txid;
        pax->vout = vout;
        HASH_ADD_KEYPTR(hh,dp->PAX,&pax->txid,sizeof(pax->txid),pax);
    }
    if ( pax != 0 )
    {
        pax->marked = mark;
        int32_t i; for (i=0; i<32; i++)
            printf("%02x",((uint8_t *)&txid)[i]);
        printf(" paxmark.ht %d vout%d\n",mark,vout);
        memcpy(space,pax,sizeof(*pax));
    }
    pthread_mutex_unlock(&dp->paxmutex);
    return(pax);
}

cJSON *dpow_withdraws_pending(struct dpow_info *dp)
{
    struct pax_transaction *pax,*tmp; cJSON *retjson = cJSON_CreateArray();
    pthread_mutex_lock(&dp->paxmutex);
    /*if ( dp->PAX != 0 )
    {
        tmp = 0;
        pax = dp->PAX->hh.next;
        while ( pax != 0 && pax != tmp )
        {
            if ( pax->marked == 0 )
                jaddi(retjson,dpow_paxjson(pax));
            tmp = pax;
            pax = pax->hh.next;
        }
    }*/
    HASH_ITER(hh,dp->PAX,pax,tmp)
    {
        if ( pax->marked == 0 )
            jaddi(retjson,dpow_paxjson(pax));
    }
    pthread_mutex_unlock(&dp->paxmutex);
    return(retjson);
}

void dpow_issuer_withdraw(struct dpow_info *dp,char *coinaddr,uint64_t fiatoshis,int32_t shortflag,char *symbol,uint64_t komodoshis,uint8_t *rmd160,bits256 txid,uint16_t vout,int32_t kmdheight,int32_t height) // assetchain context
{
    struct pax_transaction *pax;
    pthread_mutex_lock(&dp->paxmutex);
    HASH_FIND(hh,dp->PAX,&txid,sizeof(txid),pax);
    if ( pax == 0 )
    {
        pax = (struct pax_transaction *)calloc(1,sizeof(*pax));
        pax->txid = txid;
        pax->vout = vout;
        HASH_ADD_KEYPTR(hh,dp->PAX,&pax->txid,sizeof(pax->txid),pax);
    }
    pthread_mutex_unlock(&dp->paxmutex);
    if ( coinaddr != 0 )
    {
        strcpy(pax->coinaddr,coinaddr);
        pax->komodoshis = komodoshis;
        pax->shortflag = shortflag;
        strcpy(pax->symbol,symbol);
        pax->fiatoshis = fiatoshis;
        memcpy(pax->rmd160,rmd160,20);
        pax->kmdheight = kmdheight;
        pax->height = height;
        if ( pax->marked == 0 )
            printf("ADD WITHDRAW %s %.8f -> %s %.8f TO PAX kht.%d ht.%d\n",symbol,dstr(pax->fiatoshis),coinaddr,dstr(pax->komodoshis),kmdheight,height);
        else printf("MARKED WITHDRAW %s %.8f -> %s %.8f TO PAX kht.%d ht.%d\n",symbol,dstr(pax->fiatoshis),coinaddr,dstr(pax->komodoshis),kmdheight,height);
    }
    else
    {
        pax->marked = height;
        printf("MARK WITHDRAW ht.%d\n",height);
    }
}

void dpow_issuer_voutupdate(struct dpow_info *dp,char *symbol,int32_t isspecial,int32_t height,int32_t txi,bits256 txid,int32_t vout,int32_t numvouts,int64_t fiatoshis,uint8_t *script,int32_t len)
{
    char base[16],destaddr[64],coinaddr[64]; uint8_t addrtype,shortflag,rmd160[20],pubkey33[33]; int64_t checktoshis,komodoshis; uint64_t seed; struct pax_transaction space; int32_t i,kmdheight,opretlen,offset = 0;
    if ( script[offset++] == 0x6a )
    {
        memset(base,0,sizeof(base));
        offset += dpow_scriptitemlen(&opretlen,&script[offset]);
        if ( script[offset] == 'W' && strcmp(dp->symbol,"KMD") != 0 )
        {
            // if valid add to pricefeed for issue
            printf("WITHDRAW ht.%d txi.%d vout.%d %.8f opretlen.%d\n",height,txi,vout,dstr(fiatoshis),opretlen);
            if ( opretlen == 38 ) // any KMD tx
            {
                offset++;
                offset += PAX_pubkey(0,&script[offset],&addrtype,rmd160,base,&shortflag,&komodoshis);
                iguana_rwnum(0,&script[offset],sizeof(kmdheight),&kmdheight);
                if ( komodoshis < 0 )
                    komodoshis = -komodoshis;
                bitcoin_address(coinaddr,addrtype,rmd160,20);
                checktoshis = PAX_fiatdest(&seed,1,destaddr,pubkey33,coinaddr,kmdheight,base,fiatoshis);
                for (i=0; i<32; i++)
                    printf("%02x",((uint8_t *)&txid)[i]);
                printf(" <- txid.v%u ",vout);
                for (i=0; i<33; i++)
                    printf("%02x",pubkey33[i]);
                printf(" checkpubkey fiat %.8f check %.8f vs komodoshis %.8f dest.(%s) kmdheight.%d ht.%d seed.%llu\n",dstr(fiatoshis),dstr(checktoshis),dstr(komodoshis),destaddr,kmdheight,height,(long long)seed);
                if ( shortflag == 0 )
                {
                    if ( seed == 0 || checktoshis >= komodoshis )
                    {
                        if ( dpow_paxfind(dp,&space,txid,vout) == 0 )
                            dpow_issuer_withdraw(dp,coinaddr,fiatoshis,shortflag,base,komodoshis,rmd160,txid,vout,kmdheight,height);
                    }
                }
                else // short
                {
                    printf("shorting not yet, wait for pax2\n");
                    /*for (i=0; i<opretlen; i++)
                        printf("%02x",script[i]);
                    printf(" opret[%c] fiatoshis %.8f vs check %.8f\n",script[0],dstr(fiatoshis),dstr(checktoshis));
                    if ( seed == 0 || fiatoshis < checktoshis )
                    {
                        
                    }*/
                }
            }
        }
        else if ( script[offset] == 'X' && strcmp(dp->symbol,"KMD") == 0 )
        {
            printf("WITHDRAW issued ht.%d txi.%d vout.%d %.8f\n",height,txi,vout,dstr(fiatoshis));
            if ( opretlen == 46 ) // any KMD tx
            {
                offset++;
                offset += PAX_pubkey(0,&script[offset],&addrtype,rmd160,base,&shortflag,&fiatoshis);
                iguana_rwnum(0,&script[offset],sizeof(kmdheight),&kmdheight);
                iguana_rwnum(0,&script[offset],sizeof(height),&height);
                if ( fiatoshis < 0 )
                    fiatoshis = -fiatoshis;
                bitcoin_address(coinaddr,addrtype,rmd160,20);
                checktoshis = PAX_fiatdest(&seed,1,destaddr,pubkey33,coinaddr,kmdheight,base,fiatoshis);
                for (i=0; i<32; i++)
                    printf("%02x",((uint8_t *)&txid)[i]);
                printf(" <- txid.v%u ",vout);
                for (i=0; i<33; i++)
                    printf("%02x",pubkey33[i]);
                printf(" checkpubkey check %.8f v %.8f dest.(%s) height.%d\n",dstr(checktoshis),dstr(fiatoshis),destaddr,height);
                if ( shortflag == 0 )
                {
                    if ( seed == 0 || checktoshis > fiatoshis )
                    {
                        dpow_paxmark(dp,&space,txid,vout,height);
                    }
                }
                else
                {
                    printf("shorting not yet, wait for pax2\n");
                }
            }
        }
    }
}

int32_t dpow_issuer_tx(int32_t *isspecialp,struct dpow_info *dp,struct iguana_info *coin,int32_t height,int32_t txi,char *txidstr,uint32_t port)
{
    char *retstr,params[256],*hexstr; uint8_t script[16384]; cJSON *json,*oldpub,*newpub,*result,*vouts,*item,*sobj; int32_t vout,n,len,retval = -1; uint64_t value; bits256 txid;
    sprintf(params,"[\"%s\", 1]",txidstr);
    *isspecialp = 0;
    if ( (retstr= dpow_issuemethod(coin->chain->userpass,(char *)"getrawtransaction",params,port)) != 0 )
    {
        if ( (json= cJSON_Parse(retstr)) != 0 )
        {
            //printf("TX.(%s)\n",retstr);
            if ( (result= jobj(json,(char *)"result")) != 0 )
            {
                oldpub = jobj(result,(char *)"vpub_old");
                newpub = jobj(result,(char *)"vpub_new");
                retval = 0;
                if ( oldpub == 0 && newpub == 0 && (vouts= jarray(&n,result,(char *)"vout")) != 0 )
                {
                    txid = jbits256(result,(char *)"txid");
                    for (vout=0; vout<n; vout++)
                    {
                        item = jitem(vouts,vout);
                        value = SATOSHIDEN * jdouble(item,(char *)"value");
                        if ( (sobj= jobj(item,(char *)"scriptPubKey")) != 0 )
                        {
                            if ( (hexstr= jstr(sobj,(char *)"hex")) != 0 )
                            {
                                len = (int32_t)strlen(hexstr) >> 1;
                                if ( vout == 0 && ((memcmp(&hexstr[2],CRYPTO777_PUBSECPSTR,66) == 0 && len == 35) || (memcmp(&hexstr[6],CRYPTO777_RMD160STR,40) == 0 && len == 25)) )
                                    *isspecialp = 1;
                                else if ( len <= sizeof(script) )
                                {
                                    decode_hex(script,len,hexstr);
                                    dpow_issuer_voutupdate(dp,coin->symbol,*isspecialp,height,txi,txid,vout,n,value,script,len);
                                }
                            }
                        }
                    }
                }
            } else printf("error getting txids.(%s)\n",retstr);
            free_json(json);
        }
        free(retstr);
    }
    return(retval);
}

int32_t dpow_issuer_block(struct dpow_info *dp,struct iguana_info *coin,int32_t height,uint16_t port)
{
    char *retstr,*retstr2,params[128],*txidstr; int32_t i,isspecial,n,retval = -1; cJSON *json,*tx=0,*result=0,*result2;
    sprintf(params,"[%d]",height);
    if ( (retstr= dpow_issuemethod(coin->chain->userpass,(char *)"getblockhash",params,port)) != 0 )
    {
        if ( (result= cJSON_Parse(retstr)) != 0 )
        {
            if ( (txidstr= jstr(result,(char *)"result")) != 0 && strlen(txidstr) == 64 )
            {
                sprintf(params,"[\"%s\"]",txidstr);
                if ( (retstr2= dpow_issuemethod(coin->chain->userpass,(char *)"getblock",params,port)) != 0 )
                {
                    //printf("getblock.(%s)\n",retstr2);
                    if ( (json= cJSON_Parse(retstr2)) != 0 )
                    {
                        if ( (result2= jobj(json,(char *)"result")) != 0 && (tx= jarray(&n,result2,(char *)"tx")) != 0 )
                        {
                            for (i=0; i<n; i++)
                                if ( dpow_issuer_tx(&isspecial,dp,coin,height,i,jstri(tx,i),port) < 0 )
                                    break;
                            if ( i == n )
                                retval = 0;
                            else printf("dpow_issuer_block ht.%d error i.%d vs n.%d\n",height,i,n);
                        } else printf("cant get result.%p or tx.%p\n",result,tx);
                        free_json(json);
                    } else printf("cant parse2.(%s)\n",retstr2);
                    free(retstr2);
                } else printf("error getblock %s\n",params);
            } else printf("strlen.%ld (%s)\n",strlen(txidstr),txidstr);
            free_json(result);
        } else printf("couldnt parse.(%s)\n",retstr);
        free(retstr);
    } else printf("error from getblockhash %d\n",height);
    return(retval);
}

int32_t dpow_issuer_iteration(struct dpow_info *dp,struct iguana_info *coin,int32_t height,uint32_t *isrealtimep)
{
    char *retstr; int32_t i,currentheight=0; cJSON *infoobj,*result; uint16_t port = coin->chain->rpcport;
    if ( height <= 0 )
        height = 1;
    *isrealtimep = 0;
    if ( (retstr= dpow_issuemethod(coin->chain->userpass,(char *)"getinfo",0,port)) != 0 )
    {
        if ( (infoobj= cJSON_Parse(retstr)) != 0 )
        {
            if ( (result= jobj(infoobj,(char *)"result")) != 0 && (currentheight= jint(result,(char *)"blocks")) != 0 )
            {
                for (i=0; i<500 && height<=currentheight; i++,height++)
                {
                    /*fprintf(stderr,"%s.%d ",coin->symbol,height);
                    if ( (height % 10) == 0 )
                    {
                        if ( (height % 100) == 0 )
                            fprintf(stderr,"%s.%d ",coin->symbol,height);
                        memset(&zero,0,sizeof(zero));
                        komodo_stateupdate(height,0,0,0,zero,0,0,0,0,height,0,0,0,0,0);
                    }*/
                    if ( dpow_issuer_block(dp,coin,height,port) < 0 )
                    {
                        printf("error height %d\n",height);
                        break;
                    }
                    usleep(10000);
                }
                if ( height >= currentheight )
                    *isrealtimep = (uint32_t)time(NULL);
            }
            free_json(infoobj);
        }
        //printf("GETINFO.(%s)\n",retstr);
        free(retstr);
    }
    else
    {
        printf("error from %s height.%d currentheight.%d\n",coin->symbol,height,currentheight);
        usleep(100000);
    }
    //printf("[%s -> %s] %s ht.%d current.%d\n",dp->symbol,dp->dest,coin->symbol,height,currentheight);
    return(height);
}

