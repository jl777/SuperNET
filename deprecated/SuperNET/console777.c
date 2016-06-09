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
#ifdef notyet

#ifdef DEFINES_ONLY
#ifndef crypto777_console777_h
#define crypto777_console777_h
#include <stdio.h>
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "../includes/cJSON.h"
#include "../KV/kv777.c"
#include "../common/system777.c"

#endif
#else
#ifndef crypto777_console777_c
#define crypto777_console777_c

#ifndef crypto777_console777_h
#define DEFINES_ONLY
#include "console777.c"
#undef DEFINES_ONLY
#endif

int32_t getline777(char *line,int32_t max)
{
#ifndef _WIN32
    static char prevline[1024];
    struct timeval timeout;
    fd_set fdset;
    int32_t s;
    line[0] = 0;
    FD_ZERO(&fdset);
    FD_SET(STDIN_FILENO,&fdset);
    timeout.tv_sec = 0, timeout.tv_usec = 10000;
    if ( (s= select(1,&fdset,NULL,NULL,&timeout)) < 0 )
        fprintf(stderr,"wait_for_input: error select s.%d\n",s);
    else
    {
        if ( FD_ISSET(STDIN_FILENO,&fdset) > 0 && fgets(line,max,stdin) == line )
        {
            line[strlen(line)-1] = 0;
            if ( line[0] == 0 || (line[0] == '.' && line[1] == 0) )
                strcpy(line,prevline);
            else strcpy(prevline,line);
        }
    }
    return((int32_t)strlen(line));
#else
    fgets(line, max, stdin);
    line[strlen(line)-1] = 0;
    return((int32_t)strlen(line));
#endif
}

int32_t settoken(char *token,char *line)
{
    int32_t i;
    for (i=0; i<32&&line[i]!=0; i++)
    {
        if ( line[i] == ' ' || line[i] == '\n' || line[i] == '\t' || line[i] == '\b' || line[i] == '\r' )
            break;
        token[i] = line[i];
    }
    token[i] = 0;
    return(i);
}

void update_alias(char *line)
{
    char retbuf[8192],alias[1024],*value; int32_t i,err;
    if ( (i= settoken(&alias[1],line)) < 0 )
        return;
    if ( line[i] == 0 )
        value = &line[i];
    else value = &line[i+1];
    line[i] = 0;
    alias[0] = '#';
    printf("i.%d alias.(%s) value.(%s)\n",i,alias,value);
    if ( value[0] == 0 )
        printf("warning value for %s is null\n",alias);
    kv777_findstr(retbuf,sizeof(retbuf),SUPERNET.alias,alias);
    if ( strcmp(retbuf,value) == 0 )
        printf("UNCHANGED ");
    else printf("%s ",retbuf[0] == 0 ? "CREATE" : "UPDATE");
    printf(" (%s) -> (%s)\n",alias,value);
    if ( (err= kv777_addstr(SUPERNET.alias,alias,value)) != 0 )
        printf("error.%d updating alias database\n",err);
}

char *expand_aliases(char *_expanded,char *_expanded2,int32_t max,char *line)
{
    char alias[64],value[8192],*expanded,*otherbuf;
    int32_t i,j,k,len=0,flag = 1;
    expanded = _expanded, otherbuf = _expanded2;
    while ( len < max-8192 && flag != 0 )
    {
        flag = 0;
        len = (int32_t)strlen(line);
        for (i=j=0; i<len; i++)
        {
            if ( line[i] == '#' )
            {
                if ( (k= settoken(&alias[1],&line[i+1])) <= 0 )
                    continue;
                i += k;
                alias[0] = '#';
                if ( kv777_findstr(value,sizeof(value),SUPERNET.alias,alias) != 0 )
                {
                    if ( value[0] != 0 )
                        for (k=0; value[k]!=0; k++)
                            expanded[j++] = value[k];
                    expanded[j] = 0;
                    //printf("found (%s) -> (%s) [%s]\n",alias,value,expanded);
                    flag++;
                }
            } else expanded[j++] = line[i];
        }
        expanded[j] = 0;
        line = expanded;
        if ( expanded == _expanded2 )
            expanded = _expanded, otherbuf = _expanded2;
        else expanded = _expanded2, otherbuf = _expanded;
    }
    //printf("(%s) -> (%s) len.%d flag.%d\n",line,expanded,len,flag);
    return(line);
}

char *localcommand(char *line)
{
    char *retstr;
    if ( strcmp(line,"list") == 0 )
    {
        if ( (retstr= relays_jsonstr(0,0)) != 0 )
        {
            printf("%s\n",retstr);
            free(retstr);
        }
        return(0);
    }
    else if ( strncmp(line,"alias",5) == 0 )
    {
        update_alias(line+6);
        return(0);
    }
    else if ( strcmp(line,"help") == 0 )
    {
        printf("local commands:\nhelp, list, alias <name> <any string> then #name is expanded to <any string>\n");
        printf("alias expansions are iterated, so be careful with recursive macros!\n\n");
        
        printf("<plugin name> <method> {json args} -> invokes plugin with method and args, \"myipaddr\" and \"NXT\" are default attached\n\n");
        printf("network commands: default timeout is used if not specified\n");
        printf("relay <plugin name> <method> {json args} -> will send to random relay\n");
        printf("peers <plugin name> <method> {json args} -> will send all peers\n");
        printf("!<plugin name> <method> {json args} -> sends to random relay which will send to all its peers and combine results.\n\n");
        
        printf("publish shortcut: pub <any string> -> invokes the subscriptions plugin with publish method and all subscribers will be sent <any string>\n\n");
        
        printf("direct to specific relay needs to have a direct connection established first:\nrelay direct or peers direct <ipaddr>\n");
        printf("in case you cant directly reach a specific relay with \"peers direct <ipaddr>\" you can add \"!\" and let a relay broadcast\n");
        printf("without an <ipaddr> it will connect to a random relay. Once directly connected, commands are sent by:\n");
        printf("<ipaddress> {\"plugin\":\"<name>\",\"method\":\"<methodname>\",...}\n");
        printf("responses to direct requests are sent through as a subscription feed\n\n");
        
        printf("\"relay join\" adds your node to the list of relay nodes, your node will need to stay in sync with the other relays\n");
        //printf("\"relay mailbox <64bit number> <name>\" creates synchronized storage in all relays\n");
        return(0);
    }
    return(line);
}

char *parse_expandedline(char *plugin,int32_t max,char *method,int32_t *timeoutp,char *line,int32_t broadcastflag)
{
    int32_t i,j; char numstr[64],*pubstr,*cmdstr = 0; cJSON *json; uint64_t tag; struct destbuf tmp;
    for (i=0; i<512&&line[i]!=' '&&line[i]!=0; i++)
        plugin[i] = line[i];
    plugin[i] = 0;
    *timeoutp = 0;
    pubstr = line;
    if ( strcmp(plugin,"pub") == 0 )
        strcpy(plugin,"subscriptions"), strcpy(method,"publish"), pubstr += 4;
    else if ( line[i+1] != 0 )
    {
        for (++i,j=0; i<512&&line[i]!=' '&&line[i]!=0; i++,j++)
            method[j] = line[i];
        method[j] = 0;
    } else method[0] = 0;
    if ( (json= cJSON_Parse(line+i+1)) == 0 )
        json = cJSON_CreateObject();
    if ( json != 0 )
    {
        if ( strcmp("direct",method) == 0 && cJSON_GetObjectItem(json,"myipaddr") == 0 )
            cJSON_AddItemToObject(json,"myipaddr",cJSON_CreateString(SUPERNET.myipaddr));
        if ( cJSON_GetObjectItem(json,"tag") == 0 )
            randombytes((void *)&tag,sizeof(tag)), sprintf(numstr,"%llu",(long long)tag), cJSON_AddItemToObject(json,"tag",cJSON_CreateString(numstr));
        //if ( cJSON_GetObjectItem(json,"NXT") == 0 )
        //    cJSON_AddItemToObject(json,"NXT",cJSON_CreateString(SUPERNET.NXTADDR));
        *timeoutp = juint(json,"timeout");
        if ( plugin[0] == 0 )
            strcpy(plugin,"relay");
        if ( cJSON_GetObjectItem(json,"plugin") == 0 )
            cJSON_AddItemToObject(json,"plugin",cJSON_CreateString(plugin));
        else copy_cJSON(&tmp,cJSON_GetObjectItem(json,"plugin")), safecopy(plugin,tmp.buf,max);
        if ( method[0] == 0 )
            strcpy(method,"help");
        cJSON_AddItemToObject(json,"method",cJSON_CreateString(method));
        if ( broadcastflag != 0 )
            cJSON_AddItemToObject(json,"broadcast",cJSON_CreateString("allrelays"));
        cmdstr = cJSON_Print(json), _stripwhite(cmdstr,' ');
        return(cmdstr);
    }
    else return(clonestr(pubstr));
}

char *process_user_json(char *plugin,char *method,char *cmdstr,int32_t broadcastflag,int32_t timeout)
{
    struct daemon_info *find_daemoninfo(int32_t *indp,char *name,uint64_t daemonid,uint64_t instanceid);
    uint32_t nonce; int32_t tmp,len; char *retstr;//,tokenized[8192];
    len = (int32_t)strlen(cmdstr) + 1;
//printf("userjson.(%s).%d plugin.(%s) broadcastflag.%d method.(%s)\n",cmdstr,len,plugin,broadcastflag,method);
    if ( broadcastflag != 0 || strcmp(plugin,"relay") == 0 )
    {
        if ( strcmp(method,"busdata") == 0 )
            retstr = busdata_sync(&nonce,cmdstr,broadcastflag==0?0:"allnodes",0);
        else retstr = clonestr("{\"error\":\"direct load balanced calls deprecated, use busdata\"}");
    }
    //else if ( strcmp(plugin,"peers") == 0 )
    //    retstr = nn_allrelays((uint8_t *)cmdstr,len,timeout,0);
    else if ( find_daemoninfo(&tmp,plugin,0,0) != 0 )
    {
        //len = construct_tokenized_req(tokenized,cmdstr,SUPERNET.NXTACCTSECRET,broadcastflag!=0?"allnodes":0);
        //printf("console.(%s)\n",tokenized);
        retstr = plugin_method(-1,0,1,plugin,method,0,0,cmdstr,len,timeout != 0 ? timeout : 0,0);
    }
    else retstr = clonestr("{\"error\":\"invalid command\"}");
    return(retstr);
}

// ./BitcoinDarkd SuperNET '{"plugin":"ramchain","method":"create","coin":"BTC"}'

void process_userinput(char *_line)
{
    static char *line,*line2,*match = "./BitcoinDarkd SuperNET '";
    char plugin[512],ipaddr[1024],method[512],*cmdstr,*retstr; cJSON *json; int i,j,len,timeout,broadcastflag = 0;
    len = (int32_t)strlen(match);
    if ( _line[strlen(_line)-1] == '\'' && strncmp(_line,match,len) == 0 )
    {
        _line[strlen(_line)-1] = 0;
        _line += len;
    }
    printf("%02x %02x %02x %02x %02x\n",0xff & _line[0],0xff & _line[1],0xff & _line[2],0xff & _line[3],0xff & _line[4]);
    for (i=j=0; _line[i]!=0; i++)
    {
        if ( (uint8_t)_line[i] == 0xe2 && (uint8_t)_line[i+1] == 0x80 )
        {
            if ( (uint8_t)_line[i+2] == 0x99 )
                _line[j++] = '\'', i += 2;
            else if ( (uint8_t)_line[i+2] == 0x9c || (uint8_t)_line[i+2] == 0x9d )
                _line[j++] = '"', i += 2;
            else _line[j++] = _line[i];
        }
        else _line[j++] = _line[i];
        //else if ( (uint8_t)_line[i] == 0x9c )
          //  _line[i] = '"';
    }
    _line[j++] = 0;
    if ( (json= cJSON_Parse(_line)) != 0 )
    {
        char *process_nn_message(int32_t sock,char *jsonstr);
        free_json(json);
        retstr = SuperNET_JSON(_line);
        //retstr = process_nn_message(-1,line);
        //retstr = nn_loadbalanced((uint8_t *)line,(int32_t)strlen(line)+1);
        fprintf(stderr,"console.(%s) -> (%s)\n",_line,retstr);
        return;
    }
    else
    {
        for (i=0; _line[i]!=0; i++)
            printf("(%c %02x) ",_line[i],_line[i]&0xff);
        printf("cant parse.(%s)\n",line);
    }
    printf("[%s]\n",_line);
    if ( line == 0 )
        line = calloc(1,65536), line2 = calloc(1,65536);
    expand_aliases(line,line2,65536,_line);
    if ( (line= localcommand(line)) == 0 )
        return;
    if ( line[0] == '!' )
        broadcastflag = 1, line++;
    settoken(ipaddr,line);
    printf("expands to: %s [%s] %s\n",broadcastflag != 0 ? "broadcast": "",line,ipaddr);
    if ( is_ipaddr(ipaddr) != 0 )
    {
        line += strlen(ipaddr) + 1;
        if ( (cmdstr = parse_expandedline(plugin,sizeof(plugin),method,&timeout,line,broadcastflag)) != 0 )
        {
            printf("ipaddr.(%s) (%s)\n",ipaddr,line);
            //retstr = nn_direct(ipaddr,(uint8_t *)line,(int32_t)strlen(line)+1);
            printf("deprecated (%s) -> (%s)\n",line,cmdstr);
            free(cmdstr);
        }
        return;
    }
    if ( (cmdstr= parse_expandedline(plugin,sizeof(plugin),method,&timeout,line,broadcastflag)) != 0 )
    {
        retstr = process_user_json(plugin,method,cmdstr,broadcastflag,timeout != 0 ? timeout : SUPERNET.PLUGINTIMEOUT);
        printf("CONSOLE (%s) -> (%s) -> (%s)\n",line,cmdstr,retstr);
        free(cmdstr);
    }
}

#endif
#endif

#endif
