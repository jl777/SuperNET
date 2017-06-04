
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

char *portstrs[][2] = { { "BTC", "8332" }, { "KMD", "7771" }, { "LTC", "9332" }, { "REVS", "10196" }, { "JUMBLR", "15106" }, };

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
    confname[0] = toupper(confname[0]);
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

uint16_t LP_rpcport(char *symbol)
{
    int32_t i;
    for (i=0; i<sizeof(portstrs)/sizeof(*portstrs); i++)
        if ( strcmp(portstrs[i][0],symbol) == 0 )
            return(atoi(portstrs[i][1]));
    return(0);
}

struct iguana_info *LP_coinfind(char *symbol)
{
    static struct iguana_info *LP_coins; static int32_t LP_numcoins;
    struct iguana_info *coin,cdata; int32_t i; uint16_t port;
    for (i=0; i<LP_numcoins; i++)
        if ( strcmp(LP_coins[i].symbol,symbol) == 0 )
            return(&LP_coins[i]);
    memset(&cdata,0,sizeof(cdata));
    coin = &cdata;
    safecopy(cdata.symbol,symbol,sizeof(cdata.symbol));
    port = LP_rpcport(symbol);
    sprintf(cdata.serverport,"127.0.0.1:%u",port);
    cdata.longestchain = 100000;
    cdata.txfee = 10000;
    cdata.estimatedrate = 20;
    if ( strcmp(symbol,"BTC") == 0 )
    {
        cdata.txfee = 50000;
        cdata.estimatedrate = 300;
        cdata.p2shtype = 5;
        cdata.wiftype = 128;
        LP_userpass(cdata.userpass,symbol,"","bitcoin");
    }
    else if ( strcmp(symbol,"LTC") == 0 )
    {
        cdata.pubtype = 48;
        cdata.p2shtype = 5;
        cdata.wiftype = 176;
        LP_userpass(cdata.userpass,symbol,"","litecoin");
    }
    else
    {
        cdata.pubtype = 60;
        cdata.p2shtype = 85;
        cdata.wiftype = 188;
        LP_userpass(cdata.userpass,symbol,symbol,strcmp(symbol,"KMD") == 0 ? "komodo" : symbol);
    }
    //printf("%s: (%s) (%s)\n",symbol,cdata.serverport,cdata.userpass);
    LP_coins = realloc(LP_coins,sizeof(*LP_coins) * (LP_numcoins+1));
    coin = &LP_coins[LP_numcoins++];
    *coin = cdata;
    return(coin);
}



