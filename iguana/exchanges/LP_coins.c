
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
//  LP_coins.c
//  marketmaker
//

char *portstrs[][3] = { { "BTC", "8332" }, { "KMD", "7771" } };

uint16_t LP_rpcport(char *symbol)
{
    int32_t i;
    for (i=0; i<sizeof(portstrs)/sizeof(*portstrs); i++)
        if ( strcmp(portstrs[i][0],symbol) == 0 )
            return(atoi(portstrs[i][1]));
    return(0);
}

uint16_t LP_busport(uint16_t rpcport)
{
    if ( rpcport == 8332 )
        return(8334); // BTC
    else if ( rpcport < (1 << 15) )
        return(65535 - rpcport);
    else return(rpcport+1);
}

char *parse_conf_line(char *line,char *field)
{
    line += strlen(field);
    for (; *line!='='&&*line!=0; line++)
        break;
    if ( *line == 0 )
        return(0);
    if ( *line == '=' )
        line++;
    while ( line[strlen(line)-1] == '\r' || line[strlen(line)-1] == '\n' || line[strlen(line)-1] == ' ' )
        line[strlen(line)-1] = 0;
    //printf("LINE.(%s)\n",line);
    _stripwhite(line,0);
    return(clonestr(line));
}

void LP_userpassfp(char *symbol,char *username,char *password,FILE *fp)
{
    char *rpcuser,*rpcpassword,*str,line[8192];
    rpcuser = rpcpassword = 0;
    username[0] = password[0] = 0;
    while ( fgets(line,sizeof(line),fp) != 0 )
    {
        if ( line[0] == '#' )
            continue;
        //printf("line.(%s) %p %p\n",line,strstr(line,(char *)"rpcuser"),strstr(line,(char *)"rpcpassword"));
        if ( (str= strstr(line,(char *)"rpcuser")) != 0 )
            rpcuser = parse_conf_line(str,(char *)"rpcuser");
        else if ( (str= strstr(line,(char *)"rpcpassword")) != 0 )
            rpcpassword = parse_conf_line(str,(char *)"rpcpassword");
    }
    if ( rpcuser != 0 && rpcpassword != 0 )
    {
        strcpy(username,rpcuser);
        strcpy(password,rpcpassword);
    }
    //printf("%s rpcuser.(%s) rpcpassword.(%s)\n",symbol,rpcuser,rpcpassword);
    if ( rpcuser != 0 )
        free(rpcuser);
    if ( rpcpassword != 0 )
        free(rpcpassword);
}

void LP_statefname(char *fname,char *symbol,char *assetname,char *str,char *name,char *confpath)
{
    if ( confpath != 0 && confpath[0] != 0 )
    {
        strcpy(fname,confpath);
        return;
    }
    sprintf(fname,"%s",LP_getdatadir());
#ifdef WIN32
    strcat(fname,"\\");
#else
    strcat(fname,"/");
#endif
    if ( strcmp(symbol,"BTC") == 0 )
    {
#ifdef __APPLE__
        strcat(fname,"Bitcoin");
#else
        strcat(fname,".bitcoin");
#endif
    }
    else if ( name != 0 )
    {
        char name2[64];
#ifdef __APPLE__
        int32_t len;
        strcpy(name2,name);
        name2[0] = toupper(name2[0]);
        len = (int32_t)strlen(name2);
        if ( strcmp(&name2[len-4],"coin") == 0 )
            name2[len - 4] = 'C';
#else
        name2[0] = '.';
        strcpy(name2+1,name);
#endif
       strcat(fname,name2);
    }
    else
    {
#ifdef __APPLE__
        strcat(fname,"Komodo");
#else
        strcat(fname,".komodo");
#endif
        if ( strcmp(symbol,"KMD") != 0 )
        {
#ifdef WIN32
            strcat(fname,"\\");
#else
            strcat(fname,"/");
#endif
            strcat(fname,assetname);
        }
    }
#ifdef WIN32
    strcat(fname,"\\");
#else
    strcat(fname,"/");
#endif
    strcat(fname,str);
}

int32_t LP_userpass(char *userpass,char *symbol,char *assetname,char *confroot,char *name,char *confpath)
{
    FILE *fp; char fname[512],username[512],password[512],confname[512];
    userpass[0] = 0;
    sprintf(confname,"%s.conf",confroot);
    if ( 0 )
        printf("%s (%s) %s confname.(%s) confroot.(%s)\n",symbol,assetname,name,confname,confroot);
#ifdef __APPLE__
    int32_t len;
    confname[0] = toupper(confname[0]);
    len = (int32_t)strlen(confname);
    if ( strcmp(&confname[len-4],"coin") == 0 )
        confname[len - 4] = 'C';
#endif
    LP_statefname(fname,symbol,assetname,confname,name,confpath);
    if ( (fp= fopen(fname,"rb")) != 0 )
    {
        LP_userpassfp(symbol,username,password,fp);
        sprintf(userpass,"%s:%s",username,password);
        fclose(fp);
        if ( 0 )
            printf("LP_statefname.(%s) <- %s %s %s (%s) (%s)\n",fname,name,symbol,assetname,userpass,confpath);
        return((int32_t)strlen(userpass));
    } else printf("cant open.(%s)\n",fname);
    return(-1);
}

cJSON *LP_coinjson(struct iguana_info *coin,int32_t showwif)
{
    char wifstr[128]; uint8_t tmptype; bits256 checkkey; cJSON *item = cJSON_CreateObject();
    jaddstr(item,"coin",coin->symbol);
    if ( showwif != 0 )
    {
        bitcoin_priv2wif(coin->wiftaddr,wifstr,LP_mypriv25519,coin->wiftype);
        bitcoin_wif2priv(coin->wiftaddr,&tmptype,&checkkey,wifstr);
        if ( bits256_cmp(LP_mypriv25519,checkkey) == 0 )
            jaddstr(item,"wif",wifstr);
        else jaddstr(item,"wif","error creating wif");
    }
    if ( coin->inactive != 0 )
        jaddstr(item,"status","inactive");
    else jaddstr(item,"status","active");
    if ( coin->isPoS != 0 )
        jaddstr(item,"type","PoS");
    jaddstr(item,"smartaddress",coin->smartaddr);
    jaddstr(item,"rpc",coin->serverport);
    jaddnum(item,"pubtype",coin->pubtype);
    jaddnum(item,"p2shtype",coin->p2shtype);
    jaddnum(item,"wiftype",coin->wiftype);
    jaddnum(item,"txfee",coin->txfee);
    return(item);
}

cJSON *LP_coinsjson(int32_t showwif)
{
    struct iguana_info *coin,*tmp; cJSON *array = cJSON_CreateArray();
    HASH_ITER(hh,LP_coins,coin,tmp)
    {
        jaddi(array,LP_coinjson(coin,showwif));
    }
    return(array);
}

char *LP_getcoin(char *symbol)
{
    int32_t numenabled,numdisabled; struct iguana_info *coin,*tmp; cJSON *item=0,*retjson;
    numenabled = numdisabled = 0;
    retjson = cJSON_CreateObject();
    HASH_ITER(hh,LP_coins,coin,tmp)
    {
        if ( strcmp(symbol,coin->symbol) == 0 )
            item = LP_coinjson(coin,0);
        if ( coin->inactive == 0 )
            numenabled++;
        else numdisabled++;
    }
    jaddstr(retjson,"result","success");
    jaddnum(retjson,"enabled",numenabled);
    jaddnum(retjson,"disabled",numdisabled);
    if ( item == 0 )
        item = cJSON_CreateObject();
    jadd(retjson,"coin",item);
    return(jprint(retjson,1));
}

struct iguana_info *LP_coinsearch(char *symbol)
{
    struct iguana_info *coin;
    portable_mutex_lock(&LP_coinmutex);
    HASH_FIND(hh,LP_coins,symbol,strlen(symbol),coin);
    portable_mutex_unlock(&LP_coinmutex);
    return(coin);
}

struct iguana_info *LP_coinadd(struct iguana_info *cdata)
{
    struct iguana_info *coin = calloc(1,sizeof(*coin));
    //printf("%s: (%s) (%s)\n",symbol,cdata.serverport,cdata.userpass);
    *coin = *cdata;
    portable_mutex_init(&coin->txmutex);
    portable_mutex_lock(&LP_coinmutex);
    HASH_ADD_KEYPTR(hh,LP_coins,coin->symbol,strlen(coin->symbol),coin);
    portable_mutex_unlock(&LP_coinmutex);
    return(coin);
}

int32_t LP_coininit(struct iguana_info *coin,char *symbol,char *name,char *assetname,int32_t isPoS,uint16_t port,uint8_t pubtype,uint8_t p2shtype,uint8_t wiftype,uint64_t txfee,double estimatedrate,int32_t longestchain,uint8_t wiftaddr,uint8_t taddr,uint16_t busport,char *confpath)
{
    char *name2;
    memset(coin,0,sizeof(*coin));
    safecopy(coin->symbol,symbol,sizeof(coin->symbol));
    sprintf(coin->serverport,"127.0.0.1:%u",port);
    coin->isPoS = isPoS;
    coin->taddr = taddr;
    coin->wiftaddr = wiftaddr;
    coin->longestchain = longestchain;
    coin->txfee = txfee;
    coin->pubtype = pubtype;
    coin->p2shtype = p2shtype;
    coin->wiftype = wiftype;
    coin->inactive = (uint32_t)time(NULL);
    coin->bussock = LP_coinbus(busport);
    if ( strcmp(symbol,"KMD") == 0 || (assetname != 0 && assetname[0] != 0) )
        name2 = 0;
    else name2 = name;
    if ( strcmp(symbol,"XVG") == 0 || strcmp(symbol,"CLOAK") == 0 || strcmp(symbol,"PPC") == 0 || strcmp(symbol,"BCC") == 0 || strcmp(symbol,"ORB") == 0 )
    {
        coin->noimportprivkey_flag = 1;
        printf("truncate importprivkey for %s\n",symbol);
    }
    return(LP_userpass(coin->userpass,symbol,assetname,name,name2,confpath));
}

int32_t LP_isdisabled(char *base,char *rel)
{
    struct iguana_info *coin;
    if ( base != 0 && (coin= LP_coinsearch(base)) != 0 && coin->inactive != 0 )
        return(1);
    else if ( rel != 0 && (coin= LP_coinsearch(rel)) != 0 && coin->inactive != 0 )
        return(1);
    else return(0);
}

struct iguana_info *LP_coinfind(char *symbol)
{
    struct iguana_info *coin,cdata; int32_t isinactive,isPoS,longestchain = 1; uint16_t port,busport; uint64_t txfee; double estimatedrate; uint8_t pubtype,p2shtype,wiftype; char *name,*assetname;
    if ( (coin= LP_coinsearch(symbol)) != 0 )
        return(coin);
    if ( (port= LP_rpcport(symbol)) == 0 )
        return(0);
    if ( (busport= LP_busport(port)) == 0 )
        return(0);
    isPoS = 0;
    txfee = LP_MIN_TXFEE;
    estimatedrate = 20;
    pubtype = 60;
    p2shtype = 85;
    wiftype = 188;
    assetname = "";
    if ( strcmp(symbol,"BTC") == 0 )
    {
        txfee = 0;
        estimatedrate = 300;
        pubtype = 0;
        p2shtype = 5;
        wiftype = 128;
        name = "bitcoin";
    }
    else if ( strcmp(symbol,"KMD") == 0 )
        name = "komodo";
    else return(0);
    isinactive = LP_coininit(&cdata,symbol,name,assetname,isPoS,port,pubtype,p2shtype,wiftype,txfee,estimatedrate,longestchain,0,0,busport,0) < 0;
    if ( (coin= LP_coinadd(&cdata)) != 0 )
    {
        coin->inactive = isinactive * (uint32_t)time(NULL);
        if ( strcmp(symbol,"KMD") == 0 )
            coin->inactive = 0;
        else if ( strcmp(symbol,"BTC") == 0 )
        {
            coin->inactive = (uint32_t)time(NULL) * !IAMLP;
            printf("BTC inactive.%u\n",coin->inactive);
        }
    }
    return(coin);
}

// "coins":[{"coin":"<assetchain>", "rpcport":pppp}, {"coin":"LTC", "name":"litecoin", "rpcport":9332, "pubtype":48, "p2shtype":5, "wiftype":176, "txfee":100000 }]
// {"coin":"HUSH", "name":"hush", "rpcport":8822, "taddr":28, "pubtype":184, "p2shtype":189, "wiftype":128, "txfee":10000 }

struct iguana_info *LP_coincreate(cJSON *item)
{
    struct iguana_info cdata,*coin=0; int32_t isPoS,longestchain = 1; uint16_t port; uint64_t txfee; double estimatedrate; uint8_t pubtype,p2shtype,wiftype; char *name=0,*symbol,*assetname=0;
    if ( (symbol= jstr(item,"coin")) != 0 && symbol[0] != 0 && strlen(symbol) < 16 && LP_coinfind(symbol) == 0 && (port= juint(item,"rpcport")) != 0 )
    {
        isPoS = jint(item,"isPoS");
        txfee = j64bits(item,"txfee");
        if ( (estimatedrate= jdouble(item,"estimatedrate")) == 0. )
            estimatedrate = 20;
        pubtype = juint(item,"pubtype");
        if ( (p2shtype= juint(item,"p2shtype")) == 0 )
            p2shtype = 85;
        if ( (wiftype= juint(item,"wiftype")) == 0 )
            wiftype = 188;
        if ( (assetname= jstr(item,"asset")) != 0 )
        {
            name = assetname;
            pubtype = 60;
        }
        else if ( (name= jstr(item,"name")) == 0 )
            name = symbol;
        if ( LP_coininit(&cdata,symbol,name,assetname==0?"":assetname,isPoS,port,pubtype,p2shtype,wiftype,txfee,estimatedrate,longestchain,juint(item,"wiftaddr"),juint(item,"taddr"),LP_busport(port),jstr(item,"confpath")) < 0 )
        {
            coin = LP_coinadd(&cdata);
            coin->inactive = (uint32_t)time(NULL);
        } else coin = LP_coinadd(&cdata);
    } else if ( symbol != 0 && jobj(item,"rpcport") == 0 )
        printf("SKIP %s, missing rpcport field in coins array\n",symbol);
    if ( coin != 0 && item != 0 )
    {
        if ( strcmp("KMD",coin->symbol) != 0 )
        {
            if ( jobj(item,"active") != 0 )
                coin->inactive = !jint(item,"active");
            else
            {
                if ( IAMLP == 0 || assetname != name )
                    coin->inactive = (uint32_t)time(NULL);
                else coin->inactive = 0;
            }
        } else coin->inactive = 0;
    }
    if ( coin != 0 && coin->inactive != 0 )
        printf("LPnode.%d %s inactive.%u %p vs %p\n",IAMLP,coin->symbol,coin->inactive,assetname,name);
    return(0);
}

