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

//#include "SuperNET.h"
#define IGUANA_FORMS "[ \
\
{\"disp\":\"simple explorer\",\"agent\":\"ramchain\",\"method\":\"explore\",\"fields\":[{\"skip\":1,\"field\":\"search\",\"cols\":65,\"rows\":1}]}, \
{\"disp\":\"block height\",\"agent\":\"ramchain\",\"method\":\"block\",\"fields\":[{\"field\":\"height\",\"cols\":10,\"rows\":1}]}, \
{\"disp\":\"block hash\",\"agent\":\"ramchain\",\"method\":\"block\",\"fields\":[{\"field\":\"hash\",\"cols\":65,\"rows\":1}]}, \
{\"disp\":\"txid\",\"agent\":\"ramchain\",\"method\":\"txid\",\"fields\":[{\"skip\":1,\"field\":\"hash\",\"cols\":65,\"rows\":1}]}, \
{\"disp\":\"status\",\"agent\":\"ramchain\",\"method\":\"status\",\"fields\":[{\"skip\":1,\"field\":\"coin\",\"cols\":1,\"rows\":1}]}, \
{\"disp\":\"bundleinfo\",\"agent\":\"ramchain\",\"method\":\"bundleinfo\",\"fields\":[{\"skip\":1,\"field\":\"height\",\"cols\":12,\"rows\":1}]}, \
\
{\"disp\":\"addcoin\",\"agent\":\"iguana\",\"method\":\"addcoin\",\"fields\":[{\"skip\":1,\"field\":\"coin\",\"cols\":8,\"rows\":1}]}, \
{\"disp\":\"pausecoin\",\"agent\":\"iguana\",\"method\":\"pausecoin\",\"fields\":[{\"skip\":1,\"field\":\"coin\",\"cols\":1,\"rows\":1}]}, \
{\"disp\":\"startcoin\",\"agent\":\"iguana\",\"method\":\"startcoin\",\"fields\":[{\"skip\":1,\"field\":\"coin\",\"cols\":1,\"rows\":1}]}, \
{\"disp\":\"addnode\",\"agent\":\"iguana\",\"method\":\"addnode\",\"fields\":[{\"skip\":1,\"field\":\"ipaddr\",\"cols\":32,\"rows\":1}]}, \
{\"disp\":\"maxpeers\",\"agent\":\"iguana\",\"method\":\"maxpeers\",\"fields\":[{\"skip\":1,\"field\":\"max\",\"cols\":8,\"rows\":1}]}, \
{\"disp\":\"peers\",\"agent\":\"iguana\",\"method\":\"peers\",\"fields\":[{\"field\":\"coin\",\"cols\":16,\"rows\":1}]}, \
{\"disp\":\"nodestatus\",\"agent\":\"iguana\",\"method\":\"nodestatus\",\"fields\":[{\"skip\":1,\"field\":\"ipaddr\",\"cols\":32,\"rows\":1}]}, \
\
{\"disp\":\"rates\",\"agent\":\"PAX\",\"method\":\"rates\",\"fields\":[{\"skip\":1,\"field\":\"peg\",\"cols\":16,\"rows\":1}]},\
{\"disp\":\"prices\",\"agent\":\"PAX\",\"method\":\"prices\",\"fields\":[{\"skip\":1,\"field\":\"peg\",\"cols\":16,\"rows\":1}]},\
{\"agent\":\"PAX\",\"method\":\"lock\",\"fields\":[{\"skip\":1,\"field\":\"peg\",\"cols\":16,\"rows\":1},{\"skip\":1,\"field\":\"lockdays\",\"cols\":6,\"rows\":1},{\"skip\":1,\"field\":\"units\",\"cols\":12,\"rows\":1}]}, \
{\"agent\":\"PAX\",\"method\":\"redeem\",\"fields\":[{\"skip\":1,\"field\":\"txid\",\"cols\":65,\"rows\":1},{\"skip\":1,\"field\":\"dest\",\"cols\":65,\"rows\":1}]},\
{\"disp\":\"balance\",\"agent\":\"PAX\",\"method\":\"balance\",\"fields\":[{\"skip\":1,\"field\":\"address\",\"cols\":44,\"rows\":1}]},\
{\"agent\":\"PAX\",\"method\":\"rollover\",\"fields\":[{\"skip\":1,\"field\":\"txid\",\"cols\":16,\"rows\":1},{\"skip\":1,\"field\":\"newpeg\",\"cols\":16,\"rows\":1},{\"skip\":1,\"field\":\"newlockdays\",\"cols\":6,\"rows\":1}]},\
{\"agent\":\"PAX\",\"method\":\"swap\",\"fields\":[{\"skip\":1,\"field\":\"txid\",\"cols\":16,\"rows\":1},{\"skip\":1,\"field\":\"othertxid\",\"cols\":16,\"rows\":1}]},\
{\"agent\":\"PAX\",\"method\":\"bet\",\"fields\":[{\"skip\":1,\"field\":\"peg\",\"cols\":16,\"rows\":1},{\"skip\":1,\"field\":\"price\",\"cols\":16,\"rows\":1},{\"skip\":1,\"field\":\"amount\",\"cols\":16,\"rows\":1}]},\
\
{\"agent\":\"InstantDEX\",\"method\":\"placebid\",\"fields\":[{\"skip\":1,\"field\":\"base\",\"cols\":8,\"rows\":1},{\"skip\":1,\"field\":\"rel\",\"cols\":8,\"rows\":1},{\"skip\":1,\"field\":\"exchange\",\"cols\":16,\"rows\":1},{\"field\":\"price\",\"cols\":16,\"rows\":1},{\"field\":\"volume\",\"cols\":16,\"rows\":1}]}, \
{\"agent\":\"InstantDEX\",\"method\":\"placeask\",\"fields\":[{\"skip\":1,\"field\":\"base\",\"cols\":8,\"rows\":1},{\"skip\":1,\"field\":\"rel\",\"cols\":8,\"rows\":1},{\"skip\":1,\"field\":\"exchange\",\"cols\":16,\"rows\":1},{\"field\":\"price\",\"cols\":16,\"rows\":1},{\"field\":\"volume\",\"cols\":16,\"rows\":1}]}, \
{\"agent\":\"InstantDEX\",\"method\":\"orderbook\",\"fields\":[{\"skip\":1,\"field\":\"base\",\"cols\":8,\"rows\":1},{\"skip\":1,\"field\":\"rel\",\"cols\":8,\"rows\":1},{\"skip\":1,\"field\":\"exchange\",\"cols\":16,\"rows\":1}]}, \
{\"disp\":\"orderstatus\",\"agent\":\"InstantDEX\",\"method\":\"orderstatus\",\"fields\":[{\"skip\":1,\"field\":\"orderid\",\"cols\":32,\"rows\":1}]}, \
{\"disp\":\"cancelorder\",\"agent\":\"InstantDEX\",\"method\":\"cancelorder\",\"fields\":[{\"skip\":1,\"field\":\"orderid\",\"cols\":32,\"rows\":1}]}, \
{\"disp\":\"balance\",\"agent\":\"InstantDEX\",\"method\":\"balance\",\"fields\":[{\"skip\":1,\"field\":\"exchange\",\"cols\":16,\"rows\":1}]}, \
{\"newline\":0,\"disp\":\"allorderbooks\",\"agent\":\"InstantDEX\",\"method\":\"allorderbooks\",\"fields\":[{\"skip\":1,\"field\":\"allorderbooks\",\"cols\":1,\"rows\":1}]}, \
{\"newline\":0,\"disp\":\"openorders\",\"agent\":\"InstantDEX\",\"method\":\"openorders\",\"fields\":[{\"skip\":1,\"field\":\"openorders\",\"cols\":1,\"rows\":1}]}, \
{\"newline\":0,\"disp\":\"tradehistory\",\"agent\":\"InstantDEX\",\"method\":\"tradehistory\",\"fields\":[{\"skip\":1,\"field\":\"tradehistory\",\"cols\":1,\"rows\":1}]}, \
{\"disp\":\"allexchanges\",\"agent\":\"InstantDEX\",\"method\":\"allexchanges\",\"fields\":[{\"skip\":1,\"field\":\"allexchanges\",\"cols\":1,\"rows\":1}]}, \
\
{\"agent\":\"pangea\",\"method\":\"bet\",\"fields\":[{\"skip\":1,\"field\":\"tableid\",\"cols\":24,\"rows\":1},{\"skip\":1,\"field\":\"amount\",\"cols\":24,\"rows\":1}]}, \
{\"disp\":\"call\",\"agent\":\"pangea\",\"method\":\"call\",\"fields\":[{\"skip\":1,\"field\":\"tableid\",\"cols\":1,\"rows\":1}]}, \
{\"disp\":\"fold\",\"agent\":\"pangea\",\"method\":\"fold\",\"fields\":[{\"skip\":1,\"field\":\"tableid\",\"cols\":1,\"rows\":1}]}, \
{\"disp\":\"status\",\"agent\":\"pangea\",\"method\":\"status\",\"fields\":[{\"skip\":1,\"field\":\"tableid\",\"cols\":1,\"rows\":1}]}, \
{\"disp\":\"hand history\",\"agent\":\"pangea\",\"method\":\"handhistory\",\"fields\":[{\"skip\":1,\"field\":\"tableid\",\"cols\":1,\"rows\":1}]}, \
{\"disp\":\"history\",\"agent\":\"pangea\",\"method\":\"history\",\"fields\":[{\"skip\":1,\"field\":\"coin\",\"cols\":1,\"rows\":1}]}, \
{\"disp\":\"follow\",\"agent\":\"pangea\",\"method\":\"follow\",\"fields\":[{\"skip\":1,\"field\":\"tableid\",\"cols\":24,\"rows\":1}]}, \
{\"disp\":\"lobby\",\"agent\":\"pangea\",\"method\":\"lobby\",\"fields\":[{\"skip\":1,\"field\":\"coin\",\"cols\":8,\"rows\":1}]}, \
{\"disp\":\"join\",\"agent\":\"pangea\",\"method\":\"join\",\"fields\":[{\"skip\":1,\"field\":\"tableid\",\"cols\":24,\"rows\":1}]}, \
{\"agent\":\"pangea\",\"method\":\"buyin\",\"fields\":[{\"skip\":1,\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"skip\":1,\"field\":\"tableid\",\"cols\":24,\"rows\":1},{\"skip\":1,\"field\":\"amount\",\"cols\":12,\"rows\":1}]}, \
{\"agent\":\"pangea\",\"method\":\"newtournament\",\"fields\":[{\"field\":\"mintables\",\"cols\":8,\"rows\":1},{\"field\":\"maxtables\",\"cols\":4,\"rows\":1},{\"field\":\"starttime\",\"cols\":16,\"rows\":1},{\"field\":\"prizefund\",\"cols\":12,\"rows\":1},{\"field\":\"coin\",\"cols\":12,\"rows\":1}]}, \
{\"agent\":\"pangea\",\"method\":\"newtable\",\"fields\":[{\"field\":\"minplayers\",\"cols\":4,\"rows\":1},{\"field\":\"maxplayers\",\"cols\":4,\"rows\":1},{\"field\":\"rake\",\"cols\":4,\"rows\":1},{\"field\":\"bigblind\",\"cols\":12,\"rows\":1},{\"field\":\"ante\",\"cols\":12,\"rows\":1},{\"field\":\"minbuyin\",\"cols\":12,\"rows\":1},{\"field\":\"maxbuyin\",\"cols\":12,\"rows\":1}]}, \
{\"disp\":\"leave\",\"agent\":\"pangea\",\"method\":\"leave\",\"fields\":[{\"skip\":1,\"field\":\"tableid\",\"cols\":8,\"rows\":1}]}, \
\
{\"agent\":\"jumblr\",\"method\":\"send\",\"fields\":[{\"skip\":1,\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"skip\":1,\"field\":\"amount\",\"cols\":13,\"rows\":1},{\"skip\":1,\"field\":\"address\",\"cols\":8,\"rows\":1}]}, \
{\"agent\":\"jumblr\",\"method\":\"invoice\",\"fields\":[{\"skip\":1,\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"skip\":1,\"field\":\"amount\",\"cols\":13,\"rows\":1},{\"skip\":1,\"field\":\"address\",\"cols\":8,\"rows\":1}]}, \
{\"agent\":\"jumblr\",\"method\":\"shuffle\",\"fields\":[{\"skip\":1,\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"skip\":1,\"field\":\"amount\",\"cols\":13,\"rows\":1}]}, \
{\"agent\":\"jumblr\",\"method\":\"balance\",\"fields\":[{\"skip\":1,\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"skip\":1,\"field\":\"address\",\"cols\":13,\"rows\":1}]}, \
\
{\"newline\":0,\"disp\":\"InstantDEX\",\"agent\":\"iguana\",\"method\":\"setagent\",\"fields\":[{\"field\":\"InstantDEX\",\"cols\":1,\"rows\":1}]}, \
{\"newline\":0,\"disp\":\"PAX\",\"agent\":\"iguana\",\"method\":\"setagent\",\"fields\":[{\"field\":\"PAX\",\"cols\":1,\"rows\":1}]}, \
{\"newline\":0,\"disp\":\"pangea\",\"agent\":\"iguana\",\"method\":\"setagent\",\"fields\":[{\"field\":\"pangea\",\"cols\":1,\"rows\":1}]}, \
{\"newline\":0,\"disp\":\"jumblr\",\"agent\":\"iguana\",\"method\":\"setagent\",\"fields\":[{\"field\":\"jumblr\",\"cols\":1,\"rows\":1}]}, \
{\"disp\":\"ramchain\",\"agent\":\"iguana\",\"method\":\"setagent\",\"fields\":[{\"field\":\"ramchain\",\"cols\":1,\"rows\":1}]}, \
{\"newline\":0,\"disp\":\"iguana\",\"agent\":\"iguana\",\"method\":\"setagent\",\"fields\":[{\"field\":\"iguana\",\"cols\":1,\"rows\":1}]}, \
\
{\"agent\":\"hash\",\"method\":\"NXT\",\"fields\":[{\"skip\":1,\"field\":\"password\",\"cols\":100,\"rows\":1}]}, \
{\"agent\":\"hash\",\"method\":\"curve25519\",\"fields\":[{\"skip\":1,\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"rmd160_sha256\",\"fields\":[{\"skip\":1,\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"sha256_sha256\",\"fields\":[{\"skip\":1,\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"base64_encode\",\"fields\":[{\"skip\":1,\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"base64_decode\",\"fields\":[{\"skip\":1,\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"crc32\",\"fields\":[{\"skip\":1,\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"sha512\",\"fields\":[{\"skip\":1,\"skip\":1,\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"sha384\",\"fields\":[{\"skip\":1,\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"sha256\",\"fields\":[{\"skip\":1,\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"sha224\",\"fields\":[{\"skip\":1,\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"rmd320\",\"fields\":[{\"skip\":1,\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"rmd256\",\"fields\":[{\"skip\":1,\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"rmd160\",\"fields\":[{\"skip\":1,\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"rmd128\",\"fields\":[{\"skip\":1,\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"sha1\",\"fields\":[{\"skip\":1,\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"md2\",\"fields\":[{\"skip\":1,\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"md4\",\"fields\":[{\"skip\":1,\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"md5\",\"fields\":[{\"skip\":1,\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"tiger\",\"fields\":[{\"skip\":1,\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"whirlpool\",\"fields\":[{\"skip\":1,\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"hmac_sha512\",\"fields\":[{\"skip\":1,\"field\":\"password\",\"cols\":32,\"rows\":1},{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"hmac_sha384\",\"fields\":[{\"skip\":1,\"field\":\"password\",\"cols\":32,\"rows\":1},{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"hmac_sha256\",\"fields\":[{\"skip\":1,\"field\":\"password\",\"cols\":32,\"rows\":1},{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"hmac_sha224\",\"fields\":[{\"skip\":1,\"field\":\"password\",\"cols\":32,\"rows\":1},{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"hmac_rmd320\",\"fields\":[{\"skip\":1,\"field\":\"password\",\"cols\":32,\"rows\":1},{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"hmac_rmd256\",\"fields\":[{\"skip\":1,\"field\":\"password\",\"cols\":32,\"rows\":1},{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"hmac_rmd160\",\"fields\":[{\"skip\":1,\"field\":\"password\",\"cols\":32,\"rows\":1},{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"hmac_rmd128\",\"fields\":[{\"skip\":1,\"field\":\"password\",\"cols\":32,\"rows\":1},{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"hmac_sha1\",\"fields\":[{\"skip\":1,\"field\":\"password\",\"cols\":32,\"rows\":1},{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"hmac_md2\",\"fields\":[{\"skip\":1,\"field\":\"password\",\"cols\":32,\"rows\":1},{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"hmac_md4\",\"fields\":[{\"skip\":1,\"field\":\"password\",\"cols\":32,\"rows\":1},{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"hmac_md5\",\"fields\":[{\"skip\":1,\"field\":\"password\",\"cols\":32,\"rows\":1},{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"hmac_tiger\",\"fields\":[{\"skip\":1,\"field\":\"password\",\"cols\":32,\"rows\":1},{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"hmac_whirlpool\",\"fields\":[{\"skip\":1,\"field\":\"password\",\"cols\":32,\"rows\":1},{\"field\":\"message\",\"cols\":64,\"rows\":3}]}\
]"

char *HTMLheader =
"<!DOCTYPE HTML> \
<html style=\"overflow-y:scroll;-webkit-user-select: text\"> \
<head> \
<meta http-equiv=\"Pragma\" content=\"no-cache\"> \
<meta http-equiv=\"Expires\" content=\"-1\"> \
<title>iguana</title> \
<script src=\"jquery-2.1.4.min.js\" type=\"text/javascript\"></script> \
<link rel=\"stylesheet\" href=\"css/bootstrap.css\" type=\"text/css\"> \
\
</head> \
<body data-custom-load=\"true\" data-name=\"iguana\" data-tools=\"pnacl newlib glibc clang-newlib mac\" data-configs=\"Debug Release\" data-path=\"{tc}/{config}\">";

// <a href="./iguana/link?field=val">Link</a>

char *HTMLfooter =
"<script type=\"text/javascript\" src=\"js/util.js\"></script> \
\
<script type=\"text/javascript\" src=\"common.js\"></script> \
<script type=\"text/javascript\" src=\"example.js\"></script> \
\
<script src=\"js/bootstrap.js\" type=\"text/javascript\"></script> \
<script src=\"js/api.js\" type=\"text/javascript\" charset=\"utf-8\"></script> \
<script src=\"js/methods.js\" type=\"text/javascript\" charset=\"utf-8\"></script> \
<script src=\"js/sites.js\" type=\"text/javascript\" charset=\"utf-8\"></script> \
<script src=\"js/settings.js\" type=\"text/javascript\" charset=\"utf-8\"></script> \
<script src=\"js/jay.min.js\"></script> \
<script src=\"js/jay.ext.js\"></script> \
\
</body> \
</html>";

#define HTML_EMIT(str)  if ( (str) != 0 && (str)[0] != 0 ) strcpy(&retbuf[size],str), size += (int32_t)strlen(str)

/*
struct endpoint find_epbits(struct relay_info *list,uint32_t ipbits,uint16_t port,int32_t type)
{
    int32_t i; struct endpoint epbits;
    memset(&epbits,0,sizeof(epbits));
    if ( list != 0 && list->num > 0 )
    {
        if ( type >= 0 )
            type = nn_portoffset(type);
        for (i=0; i<list->num&&i<(int32_t)(sizeof(list->connections)/sizeof(*list->connections)); i++)
            if ( list->connections[i].ipbits == ipbits && (port == 0 || port == list->connections[i].port)  && (type < 0 || type == list->connections[i].nn) )
                return(list->connections[i]);
    }
    return(epbits);
}

int32_t add_relay(struct relay_info *list,struct endpoint epbits)
{
    list->connections[list->num % (sizeof(list->connections)/sizeof(*list->connections))] = epbits, list->num++;
    if ( list->num > (sizeof(list->connections)/sizeof(*list->connections)) )
        printf("add_relay warning num.%d > %ld\n",list->num,(long)(sizeof(list->connections)/sizeof(*list->connections)));
    return(list->num);
}

int32_t nn_add_lbservers(struct supernet_info *myinfo,uint16_t port,uint16_t globalport,uint16_t relaysport,int32_t priority,int32_t sock,char servers[][MAX_SERVERNAME],int32_t num)
{
    int32_t i; char endpoint[512],pubendpoint[512]; struct endpoint epbits; uint32_t ipbits;
    if ( num > 0 && servers != 0 && nn_setsockopt(sock,NN_SOL_SOCKET,NN_SNDPRIO,&priority,sizeof(priority)) >= 0 )
    {
        for (i=0; i<num; i++)
        {
            if ( (ipbits= (uint32_t)calc_ipbits(servers[i])) == 0 )
            {
                printf("null ipbits.(%s)\n",servers[i]);
                continue;
            }
            //printf("epbits.%llx ipbits.%x %s\n",*(long long *)&epbits,(uint32_t)ipbits,endpoint);
            if ( ismyaddress(servers[i],myinfo) == 0 )
            {
                epbits = calc_epbits("tcp",ipbits,port,NN_REP);
                expand_epbits(endpoint,epbits);
                if ( nn_connect(sock,endpoint) >= 0 )
                {
                    printf("+R%s ",endpoint);
                    add_relay(&myinfo->active,epbits);
                }
                if ( myinfo->subclient >= 0 )
                {
                    if ( myinfo->iamrelay != 0 )
                    {
                        epbits = calc_epbits("tcp",ipbits,relaysport,NN_PUB);
                        expand_epbits(pubendpoint,epbits);
                        if ( nn_connect(myinfo->subclient,pubendpoint) >= 0 )
                            printf("+P%s ",pubendpoint);
                    }
                    epbits = calc_epbits("tcp",ipbits,globalport,NN_PUB);
                    expand_epbits(pubendpoint,epbits);
                    if ( nn_connect(myinfo->subclient,pubendpoint) >= 0 )
                        printf("+P%s ",pubendpoint);
                }
            }
        }
        printf("added priority.%d\n",priority);
        priority++;
    } else printf("error setting priority.%d (%s)\n",priority,nn_errstr());
    return(priority);
}

int32_t _lb_socket(struct supernet_info *myinfo,uint16_t port,uint16_t globalport,uint16_t relaysport,int32_t maxmillis,char servers[][MAX_SERVERNAME],int32_t num,char backups[][MAX_SERVERNAME],int32_t numbacks,char failsafes[][MAX_SERVERNAME],int32_t numfailsafes)
{
    int32_t lbsock,timeout,retrymillis,priority = 1;
    if ( (lbsock= nn_socket(AF_SP,NN_REQ)) >= 0 )
    {
        retrymillis = (maxmillis / 30) + 1;
        printf("!!!!!!!!!!!! lbsock.%d !!!!!!!!!!!\n",lbsock);
        if ( nn_setsockopt(lbsock,NN_SOL_SOCKET,NN_RECONNECT_IVL,&retrymillis,sizeof(retrymillis)) < 0 )
            printf("error setting NN_REQ NN_RECONNECT_IVL_MAX socket %s\n",nn_errstr());
        else if ( nn_setsockopt(lbsock,NN_SOL_SOCKET,NN_RECONNECT_IVL_MAX,&maxmillis,sizeof(maxmillis)) < 0 )
            fprintf(stderr,"error setting NN_REQ NN_RECONNECT_IVL_MAX socket %s\n",nn_errstr());
        timeout = SUPERNET_NETWORKTIMEOUT;
        if ( 1 && nn_setsockopt(lbsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout)) < 0 )
            printf("error setting NN_SOL_SOCKET NN_RCVTIMEO socket %s\n",nn_errstr());
        timeout = 100;
        if ( 1 && nn_setsockopt(lbsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout)) < 0 )
            printf("error setting NN_SOL_SOCKET NN_SNDTIMEO socket %s\n",nn_errstr());
        if ( num > 0 )
            priority = nn_add_lbservers(myinfo,port,globalport,relaysport,priority,lbsock,servers,num);
        if ( numbacks > 0 )
            priority = nn_add_lbservers(myinfo,port,globalport,relaysport,priority,lbsock,backups,numbacks);
        if ( numfailsafes > 0 )
            priority = nn_add_lbservers(myinfo,port,globalport,relaysport,priority,lbsock,failsafes,numfailsafes);
    } else printf("error getting req socket %s\n",nn_errstr());
    //printf("myinfo->lb.num %d\n",myinfo->lb.num);
    return(lbsock);
}

int32_t nn_lbsocket(struct supernet_info *myinfo,int32_t maxmillis,int32_t port,uint16_t globalport,uint16_t relaysport)
{
    char Cservers[32][MAX_SERVERNAME],Bservers[32][MAX_SERVERNAME],failsafes[4][MAX_SERVERNAME];
    int32_t n,m,lbsock,numfailsafes = 0;
    printf("redo lbsocket()\n"), exit(-1);
    //strcpy(failsafes[numfailsafes++],"5.9.56.103");
    //strcpy(failsafes[numfailsafes++],"5.9.102.210");
   // n = crackfoo_servers(Cservers,sizeof(Cservers)/sizeof(*Cservers),port);
   // m = badass_servers(Bservers,sizeof(Bservers)/sizeof(*Bservers),port);
    lbsock = _lb_socket(myinfo,port,globalport,relaysport,maxmillis,Bservers,m,Cservers,n*0,failsafes,numfailsafes);
    return(lbsock);
}

void add_standard_fields(char *request)
{
    cJSON *json; uint64_t tag;
    if ( (json= cJSON_Parse(request)) != 0 )
    {
        if ( get_API_nxt64bits(cJSON_GetObjectItem(json,"NXT")) == 0 )
        {
            randombytes((void *)&tag,sizeof(tag));
            sprintf(request + strlen(request) - 1,",\"NXT\":\"%s\",\"tag\":\"%llu\"}",myinfo->NXTADDR,(long long)tag);
            if ( myinfo->iamrelay != 0 && (myinfo->hostname[0] != 0 || myinfo->ipaddr[0] != 0) )
                sprintf(request + strlen(request) - 1,",\"iamrelay\":\"%s\"}",myinfo->hostname[0]!=0?myinfo->hostname:myinfo->myipaddr);
        }
        free_json(json);
    }
}

char *nn_loadbalanced(struct supernet_info *myinfo,uint8_t *data,int32_t len)
{
    char *msg,*jsonstr = 0;
    int32_t sendlen,i,lbsock,recvlen = 0;
    if ( (lbsock= myinfo->lbclient) < 0 )
        return(clonestr("{\"error\":\"invalid load balanced socket\"}"));
    for (i=0; i<10; i++)
        if ( (nn_socket_status(lbsock,1) & NN_POLLOUT) != 0 )
            break;
    if ( myinfo->Debuglevel > 2 )
        printf("sock.%d NN_LBSEND.(%s)\n",lbsock,data);
    //fprintf(stderr,"send to network\n");
    if ( (sendlen= nn_send(lbsock,data,len,0)) == len )
    {
        for (i=0; i<10; i++)
            if ( (nn_socket_status(lbsock,1) & NN_POLLIN) != 0 )
                break;
        if ( (recvlen= nn_recv(lbsock,&msg,NN_MSG,0)) > 0 )
        {
            if ( myinfo->Debuglevel > 2 )
                printf("LBRECV.(%s)\n",msg);
            jsonstr = clonestr((char *)msg);
            nn_freemsg(msg);
        }
        else
        {
            printf("nn_loadbalanced got recvlen.%d %s\n",recvlen,nn_errstr());
            jsonstr = clonestr("{\"error\":\"lb recv error, probably timeout\"}");
        }
    } else printf("got sendlen.%d instead of %d %s\n",sendlen,len,nn_errstr()), jsonstr = clonestr("{\"error\":\"lb send error\"}");
    return(jsonstr);
}

cJSON *relay_json(struct relay_info *list)
{
    cJSON *json,*array; char endpoint[512]; int32_t i;
    if ( list == 0 || list->num == 0 )
        return(0);
    array = cJSON_CreateArray();
    for (i=0; i<list->num&&i<(int32_t)(sizeof(list->connections)/sizeof(*list->connections)); i++)
    {
        expand_epbits(endpoint,list->connections[i]);
        jaddistr(array,endpoint);
    }
    json = cJSON_CreateObject();
    jadd(json,"endpoints",array);
    //cJSON_AddItemToObject(json,"type",cJSON_CreateString(nn_typestr(list->mytype)));
    //cJSON_AddItemToObject(json,"dest",cJSON_CreateString(nn_typestr(list->desttype)));
    jaddnum(json,"total",list->num);
    return(json);
}

char *relays_jsonstr(struct supernet_info *myinfo,char *jsonstr,cJSON *argjson)
{
    cJSON *json;
    if ( myinfo->iamrelay != 0 && myinfo->ipaddr[0] != 0 )
    {
        json = cJSON_CreateObject();
        jaddstr(json,"relay",myinfo->ipaddr);
        if ( myinfo->active.num > 0 )
            jadd(json,"relays",relay_json(&myinfo->active));
        return(jprint(json,1));
    }
    else return(clonestr("{\"error\":\"get relay list from relay\"}"));
}

int32_t init_SUPERNET_pullsock(struct supernet_info *myinfo,int32_t sendtimeout,int32_t recvtimeout)
{
    char bindaddr[64],*transportstr; int32_t iter;
    myinfo->pullsock = -1;
    if ( (myinfo->pullsock= nn_socket(AF_SP,NN_PULL)) < 0 )
    {
        printf("error creating pullsock %s\n",nn_strerror(nn_errno()));
        return(-1);
    }
    printf("got pullsock.%d\n",myinfo->pullsock);
    if ( nn_settimeouts(myinfo->pullsock,sendtimeout,recvtimeout) < 0 )
    {
        printf("error settime pullsock timeouts %s\n",nn_strerror(nn_errno()));
        return(-1);
    }
    printf("PULLsock.%d\n",myinfo->pullsock);
    for (iter=0; iter<2; iter++)
    {
        transportstr = (iter == 0) ? "ipc" : "inproc";
        sprintf(bindaddr,"%s://SuperNET.agents",transportstr);
        if ( nn_bind(myinfo->pullsock,bindaddr) < 0 )
        {
            printf("error binding pullsock to (%s) %s\n",bindaddr,nn_strerror(nn_errno()));
            return(-1);
        }
    }
    return(0);
}

void busdata_init(struct supernet_info *myinfo,int32_t sendtimeout,int32_t recvtimeout,int32_t firstiter)
{
    char endpoint[512]; int32_t i;
    myinfo->servicesock = myinfo->pubglobal = myinfo->pubrelays = myinfo->lbserver = -1;
    endpoint[0] = 0;
    if ( (myinfo->subclient= nn_createsocket(myinfo,endpoint,0,"NN_SUB",NN_SUB,0,sendtimeout,recvtimeout)) >= 0 )
    {
        myinfo->pfd[myinfo->numservers++].fd = myinfo->subclient, printf("numservers.%d\n",myinfo->numservers);
        nn_setsockopt(myinfo->subclient,NN_SUB,NN_SUB_SUBSCRIBE,"",0);
    } else printf("error creating subclient\n");
    myinfo->lbclient = nn_lbsocket(myinfo,SUPERNET_NETWORKTIMEOUT,SUPERNET_PORT + LB_OFFSET,myinfo->port + PUBGLOBALS_OFFSET,myinfo->port + PUBRELAYS_OFFSET);
    printf("LBclient.%d port.%d\n",myinfo->lbclient,SUPERNET_PORT + LB_OFFSET);
    sprintf(endpoint,"%s://%s:%u",myinfo->transport,myinfo->ipaddr,myinfo->serviceport);
    if ( (myinfo->servicesock= nn_createsocket(myinfo,endpoint,1,"NN_REP",NN_REP,myinfo->serviceport,sendtimeout,recvtimeout)) >= 0 )
        myinfo->pfd[myinfo->numservers++].fd = myinfo->servicesock, printf("numservers.%d\n",myinfo->numservers);
    else printf("error creating servicesock\n");
    for (i=0; i<myinfo->numservers; i++)
        myinfo->pfd[i].events = NN_POLLIN | NN_POLLOUT;
    printf("myinfo->iamrelay %d, numservers.%d ipaddr.(%s://%s) port.%d serviceport.%d\n",myinfo->iamrelay,myinfo->numservers,myinfo->transport,myinfo->ipaddr,myinfo->port,myinfo->serviceport);
}

void SuperNET_init(struct supernet_info *myinfo,char *jsonstr)
{
    char *str;
    if ( jsonstr != 0 && (str= SuperNET_JSON(myinfo,jsonstr)) != 0 )
        free(str);
    busdata_init(myinfo,10,1,0);
    init_SUPERNET_pullsock(myinfo,10,10);
}*/

int32_t Supernet_lineparse(char *key,int32_t keymax,char *value,int32_t valuemax,char *src)
{
    int32_t a,b,c,n = 0;
    key[0] = value[0] = 0;
    while ( (c= src[n]) == ' ' || c == '\t' || c == '\n' || c == '\t' )
        n++;
    while ( (c= src[n]) != ':' && c != 0 )
    {
        *key++ = c;
        if ( ++n >= keymax-1 )
        {
            *key = 0;
            printf("lineparse overflow key.(%s)\n",src);
            return(-1);
        }
    }
    *key = 0;
    if ( src[n] != ':' )
        return(n);
    n++;
    while ( (c= src[n]) == ' ' || c == '\t' )
        n++;
    while ( (c= src[n]) != 0 && c != '\r' && c != '\n' )
    {
        if ( c == '%' && (a= src[n+1]) != 0 && (b= src[n+2]) != 0 )
            c = ((unhex(a) << 4) | unhex(b)), n += 2;
        *value++ = c;
        n++;
        if ( n >= valuemax-1 )
        {
            *value = 0;
            printf("lineparse overflow.(%s)\n",src);
            return(-1);
        }
    }
    *value = 0;
    if ( src[n] != 0 )
    {
        n++;
        while ( (c= src[n]) == '\r' || c == '\n' )
            n++;
    }
    return(n);
}

cJSON *SuperNET_urlconv(char *value,int32_t bufsize,char *urlstr)
{
    int32_t i,n,totallen,datalen,len = 0; cJSON *json,*array; char key[8192],*data;
    json = cJSON_CreateObject();
    array = cJSON_CreateArray();
    totallen = (int32_t)strlen(urlstr);
    while ( 1 )
    {
        for (i=len; urlstr[i]!=0; i++)
            if ( urlstr[i] == '\r' || urlstr[i] == '\n' )
                break;
        if ( i == len && (urlstr[len] == '\r' || urlstr[len] == '\n') )
        {
            len++;
            continue;
        }
        urlstr[i] = 0;
        if ( (n= Supernet_lineparse(key,sizeof(key),value,bufsize,&urlstr[len])) > 0 )
        {
            if ( value[0] != 0 )
                jaddstr(json,key,value);
            else jaddistr(array,key);
            len += (n + 1);
            if ( strcmp(key,"Content-Length") == 0 && (datalen= atoi(value)) > 0 )
            {
                data = &urlstr[totallen - datalen];
                data[-1] = 0;
                //printf("post.(%s) (%c)\n",data,data[0]);
                jaddstr(json,"POST",data);
            }
        } else break;
    }
    jadd(json,"lines",array);
    return(json);
}

char *SuperNET_rpcparse(struct supernet_info *myinfo,char *retbuf,int32_t bufsize,int32_t *postflagp,char *urlstr,char *remoteaddr)
{
    cJSON *tokens,*argjson,*json = 0; char urlmethod[16],*data,url[1024],*retstr,*token = 0; int32_t i,j,n;
    //printf("rpcparse.(%s)\n",urlstr);
    for (i=0; i<sizeof(urlmethod)-1&&urlstr[i]!=0&&urlstr[i]!=' '; i++)
        urlmethod[i] = urlstr[i];
    urlmethod[i++] = 0;
    n = i;
    //printf("URLMETHOD.(%s)\n",urlmethod);
    *postflagp = (strcmp(urlmethod,"POST") == 0);
    for (i=0; i<sizeof(url)-1&&urlstr[n+i]!=0&&urlstr[n+i]!=' '; i++)
        url[i] = urlstr[n+i];
    url[i++] = 0;
    n += i;
    //printf("URL.(%s)\n",url);
    tokens = cJSON_CreateArray();
    j = 0;
    if ( url[0] != '/' )
        token = url;
    for (i=0; url[i]!=0; i++)
    {
        if ( url[i] == '/' )
        {
            url[i] = 0;
            if ( token != 0 )
                jaddistr(tokens,token);
            token = &url[i+1];
            continue;
        }
    }
    if ( token != 0 )
        jaddistr(tokens,token);
    if ( (json= SuperNET_urlconv(retbuf,bufsize,urlstr+n)) != 0 )
    {
        jadd(json,"tokens",tokens);
        jaddstr(json,"urlmethod",urlmethod);
        if ( (data= jstr(json,"POST")) == 0 || (argjson= cJSON_Parse(data)) == 0 )
        {
            argjson = cJSON_CreateObject();
            if ( (n= cJSON_GetArraySize(tokens)) > 0 )
            {
                jaddstr(argjson,"agent",jstri(tokens,0));
                if ( n > 1 )
                    jaddstr(argjson,"method",jstri(tokens,1));
                for (i=2; i<n; i++)
                {
                    if ( i == n-1 )
                        jaddstr(argjson,"data",jstri(tokens,i));
                    else
                    {
                        jaddstr(argjson,jstri(tokens,i),jstri(tokens,i+1));
                        i++;
                    }
                }
            }
        }
        retstr = SuperNET_JSON(myinfo,argjson,remoteaddr);
        printf("(%s) -> (%s) postflag.%d (%s)\n",urlstr,cJSON_Print(json),*postflagp,jprint(argjson,0));
        return(retstr);
    }
    return(clonestr("{\"error\":\"couldnt process packet\"}"));
}

#ifdef notyet
int32_t iguana_htmlgen(char *retbuf,int32_t bufsize,char *result,char *error,cJSON *json,char *tabname,char *origjsonstr)
{
    char *url = "http://127.0.0.1:7778";
    int i,j,m,size = 0,n,rows,cols; cJSON *array,*obj,*array2,*item,*tmp;
    char formheader[512],formfooter[512],clickname[512],buf[512],fieldbuf[512],fieldindex[2],postjson[8192];
    char *disp,*fieldname,*button,*agent,*method,*str;
    bufsize--;
    HTML_EMIT("<html> <head></head> <body> <p id=\"RTstats\"></p> ");
    sprintf(buf,"<canvas id=\"canvas\" width=\"%d\" height=\"%d\"></canvas><script>var Width = %d; var Height = %d;",IGUANA_WIDTH,IGUANA_HEIGHT,IGUANA_WIDTH,IGUANA_HEIGHT);
    HTML_EMIT(buf);
    HTML_EMIT("var RTparsed = 0; var RTcount = 0; var RTpending = 0; var RTwidth; var RTheight; var RTamplitude; var RTname; var RTjson;");
    sprintf(buf,"setInterval(iguana_poll,%d);",IGUANS_JSMILLIS);
    HTML_EMIT(buf);
    HTML_EMIT("\
  \
  function process_bitmap(bitmapjson) \
  {\
      var red,green,blue,n,m; var bitmap = JSON.parse(bitmapjson); \
      var canvas = document.getElementById(\"canvas\"); \
      var ctx = canvas.getContext(\"2d\"); \
      var image = ctx.getImageData(0,0,Width,Height); \
      RTamplitude = bitmap.amplitude / 255; \
      RTname = bitmap.status; \
      RTjson = bitmapjson; RTwidth = bitmap.width; RTheight = bitmap.height; \
      red = 0; blue = 0; green = 0; n = 0; m = 0;\
      for (y=0; y<Height; y++)\
      {\
          for (x=0; x<Width; x++)\
          {\
              image.data[m++] = bitmap.pixels[n++]; image.data[m++] = bitmap.pixels[n++]; image.data[m++] = bitmap.pixels[n++]; image.data[m++] = 255; \
          }\
      }\
      ctx.putImageData(image,0,0);\
      RTcount++;\
      RTparsed = 1;\
  }\
  \
  function bitmap_handler() \
  { \
      if ( this.status == 200 && this.responseText != null ) \
      { \
          process_bitmap(this.responseText); \
          if ( RTpending > 0 ) \
              RTpending--; \
      } \
  } \
  \
  function httpGet()\
  {\
      var client;\
      if (window.XMLHttpRequest)\
          client = new XMLHttpRequest();\
      else client = new ActiveXObject(\"Microsoft.XMLHTTP\");\
      client.onload = bitmap_handler;\
      client.open(\"GET\",\"http://127.0.0.1:7778/api/bitmap\");\
      client.send();\
  }\
  \
  function iguana_poll( )\
  { \
      var y,x,m,red,green,blue; \
      document.getElementById(\"RTstats\").innerHTML = RTcount + ' ' + RTname;\
      if ( RTpending == 0 )\
      {\
          httpGet();\
          RTpending++;\
      }\
  } </script><br>");
    //sprintf(buf,"<br> COIN: <textarea cols=\"8\" rows=\"1\"  name=\"COIN_NAME\"/>name</textarea>");
    //HTML_EMIT(buf);
    //HTML_EMIT("   Agent:    "); HTML_EMIT(Default_agent);
    
    HTML_EMIT("<br><br/>");
    HTML_EMIT(origjsonstr); HTML_EMIT(" -> ");
    HTML_EMIT("<textarea cols=\"150\" rows=\"10\"  name=\"jsonresult\"/>");
    tmp = cJSON_Parse(result), str = cJSON_Print(tmp), free_json(tmp);
    HTML_EMIT(str); free(str);
    HTML_EMIT(error);
    HTML_EMIT("</textarea>");
    formheader[0] = formfooter[0] = 0;
    if ( (array= jarray(&n,json,"forms")) != 0 )
    {
        for (i=0; i<n; i++)
        {
            item = jitem(array,i);
            //printf("FORM[%d] of %d %s\n",i,n,jprint(item,0));
            // {"forms":[{"name":"block","agent":"ramchain","fields":[{"disp":"height of block","field":"height","cols":10,"rows":1},{"disp":"blockhash","field":"hash","cols":65,"rows":1}]}]}
            if ( (method= jstr(item,"method")) == 0 )
                method = "missing";
            sprintf(clickname,"%s%d_%s",tabname,i,method);
            if ( (button= jstr(item,"button")) == 0 )
                button = method;
            if ( (agent= jstr(item,"agent")) == 0 )
                agent = "iguana";
            if ( strncmp(Default_agent,"ALL",3) != 0 && strcmp(method,"setagent") != 0 && strncmp(Default_agent,agent,strlen(agent)) != 0 )
            {
                //printf("Default_agent.%s vs agent.(%s)\n",Default_agent,agent);
                continue;
            }
            sprintf(buf,"<script> function click_%s()\n{\n",clickname);
            HTML_EMIT(buf);
            sprintf(postjson,"%s/%s",agent,method);
            //printf("form.%s button.%s [%s]\n",formname,button,postjson);
            if ( (array2= jarray(&m,item,"fields")) != 0 )
            {
                //sprintf(buf,"COIN = document.COIN_NAME.value;\n");
                //sprintf(postjson+strlen(postjson),"/%s/' + %s + '","coin","COIN");
                for (j=0; j<m; j++)
                {
                    obj = jitem(array2,j);
                    //printf("item[%d] -> (%s)\n",j,jprint(obj,0));
                    sprintf(fieldindex,"%c",'A'+j);
                    if ( (fieldname= jstr(obj,"field")) != 0 )
                    {
                        sprintf(buf,"%s = document.%s.%s.value;\n",fieldindex,clickname,fieldname);
                        HTML_EMIT(buf);
                        //sprintf(postjson+strlen(postjson),",\"%s\":\"' + %s + '\"",fieldname,fieldindex);
                        if ( juint(obj,"skip") == 0 )
                            sprintf(postjson+strlen(postjson),"/%s/' + %s + '",fieldname,fieldindex);
                        else sprintf(postjson+strlen(postjson),"/' + %s + '",fieldindex);
                    }
                }
                //strcat(postjson,"}");
                sprintf(&retbuf[size],"location.href = '%s/%s';\n}</script>\r\n",url,postjson), size += strlen(&retbuf[size]);
                sprintf(formheader,"<form name=\"%s\" action=\"%s\" method=\"POST\" onsubmit=\"return submitForm(this);\"><table>",clickname,url);
                HTML_EMIT(formheader);
                disp = jstr(item,"disp");
                for (j=0; j<m; j++)
                {
                    obj = jitem(array2,j);
                    rows = juint(obj,"rows");
                    cols = juint(obj,"cols");
                    if ( (fieldname= jstr(obj,"field")) == 0 )
                        sprintf(fieldbuf,"%s_%c",clickname,'A'+j), fieldname = fieldbuf;
                    if ( rows == 0 && cols == 0 )
                        sprintf(buf,"<input type=\"text\" name=\"%s\"/>",fieldname);
                    else sprintf(buf,"<textarea cols=\"%d\" rows=\"%d\"  name=\"%s\"/ %s></textarea>",cols,rows,fieldname,cols == 1 ? "hidden" : "");
                    str = disp==0?jstr(obj,"disp"):disp;
                    sprintf(&retbuf[size],"<td>%s</td> <td> %s </td>\r\n",str!=0?str:fieldname,buf), size += strlen(&retbuf[size]);
                }
                sprintf(formfooter,"<td colspan=\"2\"> <input type=\"button\" value=\"%s\" onclick=\"click_%s()\" /></td> </tr>\n</table></form>",button,clickname);
                HTML_EMIT(formfooter);
            }
        }
    }
    HTML_EMIT("<br><br/>"); HTML_EMIT("</body></html>"); HTML_EMIT("<br><br/>");
    return((int32_t)strlen(retbuf));
}
#undef HTML_EMIT

char *SuperNET_htmlresponse(char *retbuf,int32_t bufsize,int32_t *remainsp,int32_t localaccess,char *retstr,int32_t freeflag)
{
    static char *html = "<html> <head></head> <body> %s </body> </html>";
    char *result=0,*error=0; int32_t n; cJSON *json,*formsjson;
    retbuf[0] = 0;
    /*if ( localaccess == 0 )
     sprintf(retbuf+strlen(retbuf),"Access-Control-Allow-Origin: *\r\n");
     else sprintf(retbuf+strlen(retbuf),"Access-Control-Allow-Origin: null\r\n");
     sprintf(retbuf+strlen(retbuf),"Access-Control-Allow-Credentials: true\r\n");
     sprintf(retbuf+strlen(retbuf),"Access-Control-Allow-Headers: Authorization, Content-Type\r\n");
     sprintf(retbuf+strlen(retbuf),"Access-Control-Allow-Methods: GET, POST\r\n");
     sprintf(retbuf+strlen(retbuf),"Cache-Control: no-cache, no-store, must-revalidate\r\n");
     sprintf(retbuf+strlen(retbuf),"Content-type: text/html\r\n");
     sprintf(retbuf+strlen(retbuf),"Content-Length: %8d\r\n\r\n",n);*/
    sprintf(retbuf+strlen(retbuf),"<!DOCTYPE HTML>\n\r");
    n = (int32_t)strlen(retbuf);
    formsjson = cJSON_Parse(IGUANA_FORMS);
    if ( (json= cJSON_Parse(retstr)) == 0 )
        json = cJSON_CreateObject();
    jadd(json,"forms",formsjson);
    error = jstr(json,"error");
    result = jstr(json,"result");
    //printf("process.(%s)\n",jprint(formsjson,0));
    n = iguana_htmlgen(&retbuf[n],bufsize-n,result,error,json,"iguana",Currentjsonstr);
    free_json(json);
    if ( n == 0 )
    {
        n = (int32_t)(strlen(html) + strlen(retstr) + 1);
        sprintf(retbuf+strlen(retbuf),html,retstr);
    }
    if ( freeflag != 0 )
        free(retstr);
    if ( n > bufsize )
    {
        printf("htmlresponse overflowed buffer[%d] with %d\n",bufsize,n);
        exit(-1);
    }
    *remainsp = n;
    return(retbuf);
}
#endif
