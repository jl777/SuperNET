/******************************************************************************
 * Copyright © 2016 jl777                                                     *
 * ALL RIGHTS RESERVED                                                        *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

#ifndef __APPLE__
#include "../iguana/iguana777.h"
#else
#include "iguana777.h"
#endif

#define STEEMIT_PLANKTON 0
#define STEEMIT_MINNOW_BALANCE 100
#define STEEMIT_MINNOW 1
#define STEEMIT_DOLPHIN_BALANCE 1000
#define STEEMIT_DOLPHIN 2
#define STEEMIT_WHALE_BALANCE 100000
#define STEEMIT_WHALE 3
#define STEEMIT_MEGAWHALE_BALANCE 1000000
#define STEEMIT_MEGAWHALE 4

#include "postingkeys.c"
#define rand_account() postingkeys[rand() % (sizeof(postingkeys)/sizeof(*postingkeys))][0]

struct vote_totals { char name[16]; uint32_t whale,nonwhale,whale_for_whale,whale_for_nonwhale,nonwhale_for_whale,nonwhale_for_nonwhale,whale_selfvote,nonwhale_selfvote; };
struct steemit_word { UT_hash_handle hh; int score,ind; char wordpair[]; };
struct steemit_vote { UT_hash_handle hh; double payout; char permlink[]; };
struct steemit_whale { UT_hash_handle hh; double stake; char whale[]; };
struct steemit_post { UT_hash_handle hh; double author_steempower,tallypower[STEEMIT_MEGAWHALE+1]; uint32_t height,author_type,tally[STEEMIT_MEGAWHALE+1]; char key[]; };

void steemit_vote(int32_t height,int32_t ind,int32_t j,cJSON *json);
void steemit_comment(int32_t height,int32_t ind,int32_t j,cJSON *json,int32_t activeflag);

struct upvote_info
{
    char upvoter[64],*author,*permlink,*voters[1000];
    int32_t numvoters,whaleids[1000]; double weights[1000]; uint32_t starttime;
};

#define issue_IGUANA(url) bitcoind_RPC(0,"curl",url,0,0,0)
void *curl_post(void **cHandlep,char *url,char *userpass,char *postfields,char *hdr0,char *hdr1,char *hdr2,char *hdr3);
int32_t USE_JAY,Startheight;

char *STEEM_getstate(char *category)
{
    static void *cHandle;
    char params[1024],url[512],*retstr;
    if ( category == 0 )
        category = "";
    sprintf(url,"http://127.0.0.1:8090");
    sprintf(params,"{\"id\":%llu,\"method\":\"call\",\"params\":[\"database_api\", \"get_state\", [\"%s\"]]}",(long long)(time(NULL)*1000 + ((int32_t)OS_milliseconds() % 1000)),category);
    retstr = curl_post(&cHandle,url,"",params,0,0,0,0);
    return(retstr);
}

char *STEEM_getblock(int32_t height)
{
    static void *cHandle;
    char params[1024],url[512],*retstr;
    sprintf(url,"http://127.0.0.1:8090");
    sprintf(params,"{\"id\":%llu,\"method\":\"call\",\"params\":[\"database_api\", \"get_block\", [%d]]}",(long long)(time(NULL)*1000 + ((int32_t)OS_milliseconds() % 1000)),height);
    retstr = curl_post(&cHandle,url,"",params,0,0,0,0);
    return(retstr);
}

char *STEEM_vote(char *voter,char *author,char *permalink,int8_t wt,int32_t forceflag)
{
    static void *cHandle; static portable_mutex_t mutex;
    char params[1024],url[512],*retstr;
    if ( cHandle == 0 )
        portable_mutex_init(&mutex);
    if ( strcmp(voter,"jl777") != 0 && strcmp(voter,"taker") != 0 && strcmp(voter,"karen13") != 0 && strcmp(voter,"proto") != 0 && strcmp(voter,"yefet") != 0 )
    {
        printf("OVERRIDE: only jl777 upvotes %s.(%s %s)\n",voter,author,permalink);
        return(clonestr("{\"error\":\"override and dont vote\"}"));
    }
    if ( forceflag == 0 && strncmp(permalink,"re-",3) == 0 )//&& (strcmp(voter,"jl777") == 0 || strcmp(voter,"taker") == 0) )
    {
        printf("OVERRIDE: no upvoting on comments.(%s %s)\n",author,permalink);
        return(clonestr("{\"error\":\"override and dont vote\"}"));
    }
    portable_mutex_lock(&mutex);
    if ( wt > 100 )
        wt = 100;
    else if ( wt < -100 )
        wt = -100;
    sprintf(url,"http://127.0.0.1:8091");
    sprintf(params,"{\"id\":%llu,\"method\":\"vote\",\"params\":[\"%s\", \"%s\", \"%s\", %d, true]}",(long long)(time(NULL)*1000 + ((int32_t)OS_milliseconds() % 1000)),voter,author,permalink,wt);
    retstr = curl_post(&cHandle,url,"",params,0,0,0,0);
    portable_mutex_unlock(&mutex);
    return(retstr);
}

char *STEEM_getcontent(char *author,char *permalink)
{
    static void *cHandle;
    char params[1024],url[512],*retstr;
    sprintf(url,"http://127.0.0.1:8090");
    sprintf(params,"{\"id\":%llu,\"method\":\"get_content\",\"params\":[\"%s\", \"%s\"]}",(long long)(time(NULL)*1000 + ((int32_t)OS_milliseconds() % 1000)),author,permalink);
    //printf("(%s %s) -> (%s)\n",author,permalink,params);
    retstr = curl_post(&cHandle,url,"",params,0,0,0,0);
    return(retstr);
}

char *STEEM_getcomments(char *author,char *permalink)
{
    static void *cHandle;
    char params[1024],url[512],*retstr;
    sprintf(url,"http://127.0.0.1:8090");
    sprintf(params,"{\"id\":%llu,\"method\":\"get_content_replies\",\"params\":[\"%s\", \"%s\"]}",(long long)(time(NULL)*1000 + ((int32_t)OS_milliseconds() % 1000)),author,permalink);
    //printf("(%s %s) -> (%s)\n",author,permalink,params);
    retstr = curl_post(&cHandle,url,"",params,0,0,0,0);
    return(retstr);
}

char *STEEM_accountinfo(char *author)
{
    static void *cHandle;
    char params[1024],url[512],*retstr;
    sprintf(url,"http://127.0.0.1:8091");
    sprintf(params,"{\"id\":%llu,\"method\":\"get_account\",\"params\":[\"%s\"]}",(long long)(time(NULL)*1000 + ((int32_t)OS_milliseconds() % 1000)),author);
    retstr = curl_post(&cHandle,url,"",params,0,0,0,0);
    return(retstr);
}

int32_t permalink_str(char *permalink,int32_t size,char *str)
{
    int32_t i,c;
    for (i=0; str[i]!=0 && i<size-1; i++)
    {
        if ( (c= str[i]) == 0 )
            break;
        if ( (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') )
        {
            
        } else c = '-';
        permalink[i] = tolower(c);
    }
    permalink[i] = 0;
    return(i);
}

char *STEEM_comment(char *author,char *usepermalink,char *parent,char *parentpermalink,char *title,char *body,char *tag)
{
    /*post_comment(string author, string permlink, string parent_author, string parent_permlink, string title, string body, string json, bool broadcast)
	"parent_author": "",
    "parent_permlink": "introduceyourself",
    "author": "jl777",
    "permlink": "steemit-is-crypto-s-first-mass-market-solution",
    "title": "steemit is crypto's first mass market solution!",
    "body": "test post"
    "json_metadata": "{\"tags\":[\"introduceyourself\",\"blockchain\",\"bitcoin\",\"networking\",\"iguana\",\"supernet\",\"bitcoindark\",\"\"],\"links\":[\"https://bitco.in/forum/forums/iguana.23/\"]}"
    curl --url "http://127.0.0.1:8091" --data "{\"id\":444,\"method\":\"post_comment\",\"params\":[\"taker\", \"test-title\", \"\", \"introduceyourself\", \"test title\", \"test body\", \"{\\\"tags\\\":[\\\"introduceyourself\\\", \\\"test\\\", \\\"\\\"]}\", true]}"*/
    static void *cHandle;
    char *params,permalink[4096],url[512],*retstr;
    params = malloc(1024*1024*10);
    if ( parent != 0 && parent[0] != 0 && strlen(parentpermalink)+strlen(parent)+8 < sizeof(permalink) )
    {
        if ( usepermalink != 0 )
            strcpy(permalink,usepermalink);
        else sprintf(permalink,"re-%s-%s-r%d",parent,parentpermalink,rand() & 0x7fffffff);
    }
    else permalink_str(permalink,sizeof(permalink),title);
    sprintf(url,"http://127.0.0.1:8091");
    if ( tag != 0 )
        sprintf(params,"{\"id\":%llu,\"method\":\"post_comment\",\"params\":[\"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"{\\\"tags\\\":[\\\"%s\\\", \\\"steem\\\", \\\"steemit\\\", \\\"test\\\", \\\"\\\"]}\", true]}",(long long)(time(NULL)*1000 + ((int32_t)OS_milliseconds() % 1000)),author,permalink,parent,parentpermalink,title,body,tag); //\\\"introduceyourself\\\",
    else sprintf(params,"{\"id\":%llu,\"method\":\"post_comment\",\"params\":[\"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"{}\", true]}",(long long)(time(NULL)*1000 + ((int32_t)OS_milliseconds() % 1000)),author,permalink,parent,parentpermalink,title,body);
    //printf("ABOUT TO POST.(%s)\n",params), getchar();
    retstr = curl_post(&cHandle,url,"",params,0,0,0,0);
    free(params);
    //printf("got.(%s)\n",retstr);
    return(retstr);
}

char *STEEM_post(char *author,char *title,char *body,char *tag)
{
    return(STEEM_comment(author,0,"",tag!=0?tag:"steemit",title,body,tag));
}

char *STEEM_gethistory(char *account,int32_t firsti,int32_t num)
{
    static void *cHandle;
    char params[1024],url[512],*retstr;
    sprintf(url,"http://127.0.0.1:8090");
    sprintf(params,"{\"id\":%llu,\"method\":\"get_account_history\",\"params\":[\"%s\", %d, %d]}",(long long)(time(NULL)*1000 + ((int32_t)OS_milliseconds() % 1000)),account,firsti,num);
    retstr = curl_post(&cHandle,url,"",params,0,0,0,0);
    //printf("(%s) -> (%s)\n",params,retstr);
    return(retstr);
}

char *IGUANA_request(char *agent,char *method,cJSON *argjson)
{
    static void *cHandle;
    char *argstr=0,*retstr,url[512];
    if ( argjson != 0 )
        argstr = jprint(argjson,0);
    sprintf(url,"http://127.0.0.1:7778/api/%s/%s",agent,method);
    retstr = curl_post(&cHandle,url,"",argstr,0,0,0,0);
    if ( argstr != 0 )
        free(argstr);
    return(retstr);
}

int32_t special_account(char *account)
{
    int32_t i;
    if ( strcmp("jl777",account) == 0 || strcmp("upvotes",account) == 0 || strcmp("taker",account) == 0 )
        return(1);
    for (i=0; i<sizeof(postingkeys)/sizeof(*postingkeys); i++)
    {
        if ( strcmp(account,postingkeys[i][0]) == 0 )
            return(1);
    }
    return(0);
}

int32_t steemit_dereference(char *_author,char *_permlink)
{
    char *retstr,author[512],permlink[4096]; cJSON *retjson,*result; int32_t depth = 0;
    safecopy(author,_author,sizeof(author));
    safecopy(permlink,_permlink,sizeof(permlink));
    while ( author[0] != 0 && depth++ < 5 )
    {
        if ( (retstr= STEEM_getcontent(author,permlink)) != 0 )
        {
            //printf("(%s %s) -> (%s)\n",author,permlink,retstr);
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                if ( (result= jobj(retjson,"result")) != 0 )
                {
                    safecopy(author,jstr(result,"parent_author"),sizeof(author));
                    safecopy(permlink,jstr(result,"parent_permlink"),sizeof(permlink));
                    if ( author[0] != 0 )
                    {
                        strcpy(_author,author);
                        strcpy(_permlink,permlink);
                    }
                } else author[0] = 0;
                free_json(retjson);
            }
            free(retstr);
        }
    }
    return(depth);
}

int32_t steemit_body(char *buf,int32_t size,char *author,char *permlink)
{
    char *retstr,*body; cJSON *retjson,*result; int32_t len = 0;
    if ( (retstr= STEEM_getcomments(author,permlink)) != 0 )
    {
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (result= jobj(retjson,"result")) != 0 )
            {
                if ( (body= jstr(result,"body")) != 0 )
                {
                    if ( (len= (int32_t)strlen(body)) > size )
                        len = size;
                    strncpy(buf,body,len);
                }
            }
            free_json(retjson);
        }
        free(retstr);
    }
    return(len);
}

int32_t steemit_power(double *powerp,char *author)
{
    char *retstr; cJSON *retjson,*result; double steempower; int32_t retval = 0;
    *powerp = 0.;
    if ( (retstr= STEEM_accountinfo(author)) != 0 )
    {
        //printf("power.(%s)\n",retstr);
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (result= jobj(retjson,"result")) != 0 )
            {
                *powerp = steempower = jdouble(result,"vesting_shares") * .001;
                if ( steempower >= STEEMIT_MINNOW_BALANCE )
                {
                    if ( steempower >= STEEMIT_DOLPHIN_BALANCE )
                    {
                        if ( steempower >= STEEMIT_WHALE_BALANCE )
                        {
                            if ( steempower >= STEEMIT_MEGAWHALE_BALANCE )
                                retval = STEEMIT_MEGAWHALE;
                            else retval = STEEMIT_WHALE;
                        } else retval = STEEMIT_DOLPHIN;
                    } else retval = STEEMIT_MINNOW;
                } else retval = STEEMIT_PLANKTON;
                //printf("%s type.%d %.3f\n",author,retval,steempower);
            } else printf("(%s) -> no result.(%s)\n",author,retstr);
            free_json(retjson);
        }
        free(retstr);
    }
    return(retval);
}
