
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

char *portstrs[][2] = { { "BTC", "8332" }, { "KMD", "7771" } };

uint16_t LP_rpcport(char *symbol)
{
    int32_t i;
    for (i=0; i<sizeof(portstrs)/sizeof(*portstrs); i++)
        if ( strcmp(portstrs[i][0],symbol) == 0 )
            return(atoi(portstrs[i][1]));
    return(0);
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

void LP_userpassfp(char *username,char *password,FILE *fp)
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
    //printf("rpcuser.(%s) rpcpassword.(%s) KMDUSERPASS.(%s) %u\n",rpcuser,rpcpassword,KMDUSERPASS,port);
    if ( rpcuser != 0 )
        free(rpcuser);
    if ( rpcpassword != 0 )
        free(rpcpassword);
}

void LP_statefname(char *fname,char *symbol,char *assetname,char *str)
{
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
    else if ( strcmp(symbol,"LTC") == 0 )
    {
#ifdef __APPLE__
        strcat(fname,"Litecoin");
#else
        strcat(fname,".litecoin");
#endif
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
    printf("LP_statefname.(%s) <- %s %s %s\n",fname,symbol,assetname,str);
}

int32_t LP_userpass(char *userpass,char *symbol,char *assetname,char *confroot)
{
    FILE *fp; char fname[512],username[512],password[512],confname[16];
    userpass[0] = 0;
    sprintf(confname,"%s.conf",confroot);
#ifdef __APPLE__
    int32_t len;
    confname[0] = toupper(confname[0]);
    len = (int32_t)strlen(confname);
    if ( strcmp(&confname[len-4],"coin") == 0 )
        confname[len - 4] = 'C';
#endif
    LP_statefname(fname,symbol,assetname,confname);
    if ( (fp= fopen(fname,"rb")) != 0 )
    {
        LP_userpassfp(username,password,fp);
        sprintf(userpass,"%s:%s",username,password);
        fclose(fp);
        return((int32_t)strlen(userpass));
    }
    return(-1);
}

cJSON *LP_coinjson(struct iguana_info *coin)
{
    cJSON *item = cJSON_CreateObject();
    jaddstr(item,"coin",coin->symbol);
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
    jaddnum(item,"estimatedrate",coin->estimatedrate);
    jaddnum(item,"txfee",coin->txfee);
    return(item);
}

static struct iguana_info *LP_coins; static int32_t LP_numcoins;
cJSON *LP_coinsjson()
{
    int32_t i; cJSON *array = cJSON_CreateArray();
    for (i=0; i<LP_numcoins; i++)
        jaddi(array,LP_coinjson(&LP_coins[i]));
    return(array);
}

void LP_coininit(struct iguana_info *coin,char *symbol,char *name,char *assetname,int32_t isPoS,uint16_t port,uint8_t pubtype,uint8_t p2shtype,uint8_t wiftype,uint64_t txfee,double estimatedrate,int32_t longestchain)
{
    memset(coin,0,sizeof(*coin));
    safecopy(coin->symbol,symbol,sizeof(coin->symbol));
    sprintf(coin->serverport,"127.0.0.1:%u",port);
    coin->isPoS = isPoS;
    coin->longestchain = longestchain;
    coin->txfee = txfee;
    coin->estimatedrate = estimatedrate;
    coin->pubtype = pubtype;
    coin->p2shtype = p2shtype;
    coin->wiftype = wiftype;
    LP_userpass(coin->userpass,symbol,assetname,name);
}

struct iguana_info *LP_coinadd(struct iguana_info *cdata)
{
    struct iguana_info *coin;
    //printf("%s: (%s) (%s)\n",symbol,cdata.serverport,cdata.userpass);
    LP_coins = realloc(LP_coins,sizeof(*LP_coins) * (LP_numcoins+1));
    coin = &LP_coins[LP_numcoins];
    *coin = *cdata;
    LP_numcoins++;
    return(coin);
}

struct iguana_info *LP_coinsearch(char *symbol)
{
    int32_t i;
    for (i=0; i<LP_numcoins; i++)
        if ( strcmp(LP_coins[i].symbol,symbol) == 0 )
            return(&LP_coins[i]);
    return(0);
}

struct iguana_info *LP_coinfind(char *symbol)
{
    struct iguana_info *coin,cdata; int32_t isPoS,longestchain = 1000000; uint16_t port; uint64_t txfee; double estimatedrate; uint8_t pubtype,p2shtype,wiftype; char *name,*assetname;
    if ( (coin= LP_coinsearch(symbol)) != 0 )
        return(coin);
    if ( (port= LP_rpcport(symbol)) == 0 )
        return(0);
    isPoS = 0;
    txfee = 10000;
    estimatedrate = 20;
    pubtype = 60;
    p2shtype = 85;
    wiftype = 188;
    assetname = "";
    if ( strcmp(symbol,"BTC") == 0 )
    {
        txfee = 50000;
        estimatedrate = 300;
        pubtype = 0;
        p2shtype = 5;
        wiftype = 128;
        name = "bitcoin";
    }
    else if ( strcmp(symbol,"KMD") == 0 )
        name = "komodo";
    else
    {
        name = symbol;
        assetname = symbol;
    }
    LP_coininit(&cdata,symbol,name,assetname,isPoS,port,pubtype,p2shtype,wiftype,txfee,estimatedrate,longestchain);
    return(LP_coinadd(&cdata));
}

// "coins":[{"coin":"<assetchain>", "rpcport":pppp}, {"coin":"LTC", "name":"litecoin", "rpcport":9332, "pubtype":48, "p2shtype":5, "wiftype":176, "txfee":100000 }]

struct iguana_info *LP_coincreate(cJSON *item)
{
    struct iguana_info cdata,*coin; int32_t isPoS,longestchain = 1000000; uint16_t port; uint64_t txfee; double estimatedrate; uint8_t pubtype,p2shtype,wiftype; char *name,*symbol,*assetname;
    if ( (symbol= jstr(item,"coin")) != 0 && symbol[0] != 0 && strlen(symbol) < 16 && LP_coinfind(symbol) == 0 && (port= juint(item,"rpcport")) != 0 )
    {
        isPoS = jint(item,"isPoS");
        if ( (txfee= j64bits(item,"txfee")) == 0 )
            txfee = 10000;
        if ( (estimatedrate= jdouble(item,"estimatedrate")) == 0. )
            estimatedrate = 20;
        if ( (pubtype= juint(item,"pubtype")) == 0 )
            pubtype = 60;
        if ( (p2shtype= juint(item,"p2shtype")) == 0 )
            p2shtype = 85;
        if ( (wiftype= juint(item,"wiftype")) == 0 )
            wiftype = 188;
        if ( (assetname= jstr(item,"asset")) != 0 )
            name = assetname;
        else if ( (name= jstr(item,"name")) == 0 )
            name = symbol;
        LP_coininit(&cdata,symbol,name,assetname==0?"":assetname,isPoS,port,pubtype,p2shtype,wiftype,txfee,estimatedrate,longestchain);
        if ( (coin= LP_coinadd(&cdata)) != 0 )
            coin->inactive = !jint(item,"active");
    }
    return(0);
}

