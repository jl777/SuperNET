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

#include "iguana777.h"
#include "SuperNET.h"

char Default_agent[64] = { "ALL" };
#define IGUANA_FORMS "[ \
\
{\"disp\":\"simple explorer\",\"agent\":\"ramchain\",\"method\":\"explore\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"search\",\"cols\":65,\"rows\":1}]}, \
{\"disp\":\"block height\",\"agent\":\"ramchain\",\"method\":\"block\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"height\",\"cols\":10,\"rows\":1}]}, \
{\"disp\":\"block hash\",\"agent\":\"ramchain\",\"method\":\"block\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"hash\",\"cols\":65,\"rows\":1}]}, \
{\"disp\":\"txid\",\"agent\":\"ramchain\",\"method\":\"txid\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"hash\",\"cols\":65,\"rows\":1}]}, \
{\"disp\":\"status\",\"agent\":\"ramchain\",\"method\":\"status\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1}]}, \
{\"disp\":\"bundleinfo\",\"agent\":\"ramchain\",\"method\":\"bundleinfo\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"height\",\"cols\":12,\"rows\":1}]}, \
\
{\"disp\":\"addcoin\",\"agent\":\"iguana\",\"method\":\"addcoin\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"coin\",\"cols\":8,\"rows\":1}]}, \
{\"disp\":\"pausecoin\",\"agent\":\"iguana\",\"method\":\"pausecoin\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"coin\",\"cols\":8,\"rows\":1}]}, \
{\"disp\":\"startcoin\",\"agent\":\"iguana\",\"method\":\"startcoin\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"coin\",\"cols\":8,\"rows\":1}]}, \
{\"disp\":\"addnode\",\"agent\":\"iguana\",\"method\":\"addnode\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"ipaddr\",\"cols\":32,\"rows\":1}]}, \
{\"disp\":\"maxpeers\",\"agent\":\"iguana\",\"method\":\"maxpeers\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"max\",\"cols\":8,\"rows\":1}]}, \
{\"disp\":\"peers\",\"agent\":\"iguana\",\"method\":\"peers\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"coin\",\"cols\":16,\"rows\":1}]}, \
{\"disp\":\"nodestatus\",\"agent\":\"iguana\",\"method\":\"nodestatus\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"ipaddr\",\"cols\":32,\"rows\":1}]}, \
\
{\"disp\":\"rates\",\"agent\":\"PAX\",\"method\":\"rates\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"peg\",\"cols\":16,\"rows\":1}]},\
{\"disp\":\"prices\",\"agent\":\"PAX\",\"method\":\"prices\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"peg\",\"cols\":16,\"rows\":1}]},\
{\"agent\":\"PAX\",\"method\":\"lock\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"peg\",\"cols\":16,\"rows\":1},{\"field\":\"lockdays\",\"cols\":6,\"rows\":1},{\"field\":\"units\",\"cols\":12,\"rows\":1}]}, \
{\"agent\":\"PAX\",\"method\":\"redeem\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"txid\",\"cols\":65,\"rows\":1},{\"field\":\"dest\",\"cols\":65,\"rows\":1}]},\
{\"disp\":\"balance\",\"agent\":\"PAX\",\"method\":\"balance\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"address\",\"cols\":44,\"rows\":1}]},\
{\"agent\":\"PAX\",\"method\":\"rollover\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"txid\",\"cols\":16,\"rows\":1},{\"field\":\"newpeg\",\"cols\":16,\"rows\":1},{\"field\":\"newlockdays\",\"cols\":6,\"rows\":1}]},\
{\"agent\":\"PAX\",\"method\":\"swap\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"txid\",\"cols\":16,\"rows\":1},{\"field\":\"othertxid\",\"cols\":16,\"rows\":1}]},\
{\"agent\":\"PAX\",\"method\":\"bet\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"peg\",\"cols\":16,\"rows\":1},{\"field\":\"price\",\"cols\":16,\"rows\":1},{\"field\":\"amount\",\"cols\":16,\"rows\":1}]},\
\
{\"agent\":\"InstantDEX\",\"method\":\"placebid\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"base\",\"cols\":8,\"rows\":1},{\"field\":\"rel\",\"cols\":8,\"rows\":1},{\"field\":\"exchange\",\"cols\":16,\"rows\":1},{\"field\":\"price\",\"cols\":16,\"rows\":1},{\"field\":\"volume\",\"cols\":16,\"rows\":1}]}, \
{\"agent\":\"InstantDEX\",\"method\":\"placeask\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"base\",\"cols\":8,\"rows\":1},{\"field\":\"rel\",\"cols\":8,\"rows\":1},{\"field\":\"exchange\",\"cols\":16,\"rows\":1},{\"field\":\"price\",\"cols\":16,\"rows\":1},{\"field\":\"volume\",\"cols\":16,\"rows\":1}]}, \
{\"agent\":\"InstantDEX\",\"method\":\"orderbook\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"base\",\"cols\":8,\"rows\":1},{\"field\":\"rel\",\"cols\":8,\"rows\":1},{\"field\":\"exchange\",\"cols\":16,\"rows\":1}]}, \
{\"disp\":\"orderstatus\",\"agent\":\"InstantDEX\",\"method\":\"orderstatus\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"orderid\",\"cols\":32,\"rows\":1}]}, \
{\"disp\":\"cancelorder\",\"agent\":\"InstantDEX\",\"method\":\"cancelorder\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"orderid\",\"cols\":32,\"rows\":1}]}, \
{\"disp\":\"balance\",\"agent\":\"InstantDEX\",\"method\":\"balance\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"exchange\",\"cols\":16,\"rows\":1}]}, \
{\"newline\":0,\"disp\":\"allorderbooks\",\"agent\":\"InstantDEX\",\"method\":\"allorderbooks\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"allorderbooks\",\"cols\":1,\"rows\":1}]}, \
{\"newline\":0,\"disp\":\"openorders\",\"agent\":\"InstantDEX\",\"method\":\"openorders\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"openorders\",\"cols\":1,\"rows\":1}]}, \
{\"newline\":0,\"disp\":\"tradehistory\",\"agent\":\"InstantDEX\",\"method\":\"tradehistory\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"tradehistory\",\"cols\":1,\"rows\":1}]}, \
{\"disp\":\"allexchanges\",\"agent\":\"InstantDEX\",\"method\":\"allexchanges\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"allexchanges\",\"cols\":1,\"rows\":1}]}, \
\
{\"agent\":\"pangea\",\"method\":\"bet\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"tableid\",\"cols\":24,\"rows\":1},{\"field\":\"amount\",\"cols\":24,\"rows\":1}]}, \
{\"disp\":\"call\",\"agent\":\"pangea\",\"method\":\"call\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"tableid\",\"cols\":1,\"rows\":1}]}, \
{\"disp\":\"fold\",\"agent\":\"pangea\",\"method\":\"fold\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"tableid\",\"cols\":1,\"rows\":1}]}, \
{\"disp\":\"status\",\"agent\":\"pangea\",\"method\":\"status\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"tableid\",\"cols\":1,\"rows\":1}]}, \
{\"disp\":\"hand history\",\"agent\":\"pangea\",\"method\":\"handhistory\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"tableid\",\"cols\":1,\"rows\":1}]}, \
{\"disp\":\"history\",\"agent\":\"pangea\",\"method\":\"history\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"coin\",\"cols\":1,\"rows\":1}]}, \
{\"disp\":\"follow\",\"agent\":\"pangea\",\"method\":\"follow\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"tableid\",\"cols\":24,\"rows\":1}]}, \
{\"disp\":\"lobby\",\"agent\":\"pangea\",\"method\":\"lobby\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"coin\",\"cols\":8,\"rows\":1}]}, \
{\"disp\":\"join\",\"agent\":\"pangea\",\"method\":\"join\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"tableid\",\"cols\":24,\"rows\":1}]}, \
{\"agent\":\"pangea\",\"method\":\"buyin\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"tableid\",\"cols\":24,\"rows\":1},{\"field\":\"amount\",\"cols\":12,\"rows\":1}]}, \
{\"agent\":\"pangea\",\"method\":\"newtournament\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"mintables\",\"cols\":8,\"rows\":1},{\"field\":\"maxtables\",\"cols\":4,\"rows\":1},{\"field\":\"starttime\",\"cols\":16,\"rows\":1},{\"field\":\"prizefund\",\"cols\":12,\"rows\":1},{\"field\":\"coin\",\"cols\":12,\"rows\":1}]}, \
{\"agent\":\"pangea\",\"method\":\"newtable\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"minplayers\",\"cols\":4,\"rows\":1},{\"field\":\"maxplayers\",\"cols\":4,\"rows\":1},{\"field\":\"rake\",\"cols\":4,\"rows\":1},{\"field\":\"bigblind\",\"cols\":12,\"rows\":1},{\"field\":\"ante\",\"cols\":12,\"rows\":1},{\"field\":\"minbuyin\",\"cols\":12,\"rows\":1},{\"field\":\"maxbuyin\",\"cols\":12,\"rows\":1}]}, \
{\"disp\":\"leave\",\"agent\":\"pangea\",\"method\":\"leave\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"tableid\",\"cols\":8,\"rows\":1}]}, \
\
{\"agent\":\"jumblr\",\"method\":\"send\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"amount\",\"cols\":13,\"rows\":1},{\"field\":\"address\",\"cols\":8,\"rows\":1}]}, \
{\"agent\":\"jumblr\",\"method\":\"invoice\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"amount\",\"cols\":13,\"rows\":1},{\"field\":\"address\",\"cols\":8,\"rows\":1}]}, \
{\"agent\":\"jumblr\",\"method\":\"shuffle\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"amount\",\"cols\":13,\"rows\":1}]}, \
{\"agent\":\"jumblr\",\"method\":\"balance\",\"fields\":[{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"coin\",\"cols\":8,\"rows\":1},{\"field\":\"address\",\"cols\":13,\"rows\":1}]}, \
\
{\"newline\":0,\"disp\":\"InstantDEX\",\"agent\":\"iguana\",\"method\":\"setagent\",\"fields\":[{\"field\":\"InstantDEX\",\"cols\":1,\"rows\":1}]}, \
{\"newline\":0,\"disp\":\"PAX\",\"agent\":\"iguana\",\"method\":\"setagent\",\"fields\":[{\"field\":\"PAX\",\"cols\":1,\"rows\":1}]}, \
{\"newline\":0,\"disp\":\"pangea\",\"agent\":\"iguana\",\"method\":\"setagent\",\"fields\":[{\"field\":\"pangea\",\"cols\":1,\"rows\":1}]}, \
{\"newline\":0,\"disp\":\"jumblr\",\"agent\":\"iguana\",\"method\":\"setagent\",\"fields\":[{\"field\":\"jumblr\",\"cols\":1,\"rows\":1}]}, \
{\"disp\":\"ramchain\",\"agent\":\"iguana\",\"method\":\"setagent\",\"fields\":[{\"field\":\"ramchain\",\"cols\":1,\"rows\":1}]}, \
{\"newline\":0,\"disp\":\"iguana\",\"agent\":\"iguana\",\"method\":\"setagent\",\"fields\":[{\"field\":\"iguana\",\"cols\":1,\"rows\":1}]}, \
\
{\"agent\":\"hash\",\"method\":\"NXT\",\"fields\":[{\"field\":\"password\",\"cols\":100,\"rows\":1}]}, \
    {\"agent\":\"hash\",\"method\":\"curve25519\",\"fields\":[{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
    {\"agent\":\"hash\",\"method\":\"rmd160_sha256\",\"fields\":[{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"sha256_sha256\",\"fields\":[{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"base64_encode\",\"fields\":[{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"base64_decode\",\"fields\":[{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
{\"agent\":\"hash\",\"method\":\"crc32\",\"fields\":[{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
    {\"agent\":\"hash\",\"method\":\"sha512\",\"fields\":[{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
    {\"agent\":\"hash\",\"method\":\"sha384\",\"fields\":[{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
    {\"agent\":\"hash\",\"method\":\"sha256\",\"fields\":[{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
    {\"agent\":\"hash\",\"method\":\"sha224\",\"fields\":[{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
    {\"agent\":\"hash\",\"method\":\"rmd320\",\"fields\":[{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
    {\"agent\":\"hash\",\"method\":\"rmd256\",\"fields\":[{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
    {\"agent\":\"hash\",\"method\":\"rmd160\",\"fields\":[{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
    {\"agent\":\"hash\",\"method\":\"rmd128\",\"fields\":[{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
    {\"agent\":\"hash\",\"method\":\"sha1\",\"fields\":[{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
    {\"agent\":\"hash\",\"method\":\"md2\",\"fields\":[{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
    {\"agent\":\"hash\",\"method\":\"md4\",\"fields\":[{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
    {\"agent\":\"hash\",\"method\":\"md5\",\"fields\":[{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
    {\"agent\":\"hash\",\"method\":\"tiger\",\"fields\":[{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
    {\"agent\":\"hash\",\"method\":\"whirlpool\",\"fields\":[{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
    {\"agent\":\"hash\",\"method\":\"hmac_sha512\",\"fields\":[{\"field\":\"password\",\"cols\":32,\"rows\":1},{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
    {\"agent\":\"hash\",\"method\":\"hmac_sha384\",\"fields\":[{\"field\":\"password\",\"cols\":32,\"rows\":1},{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
    {\"agent\":\"hash\",\"method\":\"hmac_sha256\",\"fields\":[{\"field\":\"password\",\"cols\":32,\"rows\":1},{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
    {\"agent\":\"hash\",\"method\":\"hmac_sha224\",\"fields\":[{\"field\":\"password\",\"cols\":32,\"rows\":1},{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
    {\"agent\":\"hash\",\"method\":\"hmac_rmd320\",\"fields\":[{\"field\":\"password\",\"cols\":32,\"rows\":1},{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
    {\"agent\":\"hash\",\"method\":\"hmac_rmd256\",\"fields\":[{\"field\":\"password\",\"cols\":32,\"rows\":1},{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
    {\"agent\":\"hash\",\"method\":\"hmac_rmd160\",\"fields\":[{\"field\":\"password\",\"cols\":32,\"rows\":1},{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
    {\"agent\":\"hash\",\"method\":\"hmac_rmd128\",\"fields\":[{\"field\":\"password\",\"cols\":32,\"rows\":1},{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
    {\"agent\":\"hash\",\"method\":\"hmac_sha1\",\"fields\":[{\"field\":\"password\",\"cols\":32,\"rows\":1},{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
    {\"agent\":\"hash\",\"method\":\"hmac_md2\",\"fields\":[{\"field\":\"password\",\"cols\":32,\"rows\":1},{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
    {\"agent\":\"hash\",\"method\":\"hmac_md4\",\"fields\":[{\"field\":\"password\",\"cols\":32,\"rows\":1},{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
    {\"agent\":\"hash\",\"method\":\"hmac_md5\",\"fields\":[{\"field\":\"password\",\"cols\":32,\"rows\":1},{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
    {\"agent\":\"hash\",\"method\":\"hmac_tiger\",\"fields\":[{\"field\":\"password\",\"cols\":32,\"rows\":1},{\"field\":\"message\",\"cols\":64,\"rows\":3}]}, \
    {\"agent\":\"hash\",\"method\":\"hmac_whirlpool\",\"fields\":[{\"field\":\"password\",\"cols\":32,\"rows\":1},{\"field\":\"message\",\"cols\":64,\"rows\":3}]}\
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
char Prevjsonstr[1024],Currentjsonstr[1024];

int32_t iguana_htmlgen(char *retbuf,int32_t bufsize,char *result,char *error,cJSON *json,char *tabname,char *origjsonstr)
{
    char *url = "http://127.0.0.1:7778";
    int i,j,m,size = 0,n,rows,cols; cJSON *array,*obj,*array2,*item,*tmp;
    char formheader[512],formfooter[512],clickname[512],buf[512],fieldbuf[512],fieldindex[2],postjson[8192];
    char *disp,*fieldname,*button,*agent,*method,*str;
    bufsize--;
    HTML_EMIT("<html> <head><title>SuperUGLY GUI></title></head> <body> <p id=\"RTstats\"></p> ");
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
            image.data[m++] = bitmap.pixels[n++]; \
            image.data[m++] = bitmap.pixels[n++]; \
            image.data[m++] = bitmap.pixels[n++]; \
            image.data[m++] = 255; \
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
        if ( RTpending > 0 )\
            RTpending--; \
    } \
} \
\
function httpGet()\
{\
    var client;\
    if (window.XMLHttpRequest)\
        client = new XMLHttpRequest();\
    else\
        client = new ActiveXObject(\"Microsoft.XMLHTTP\");\
    client.onload = bitmap_handler;\
    client.open(\"GET\",\"http://127.0.0.1:7778/api/bitmap/BTCD\");\
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
    HTML_EMIT("<br><br/>");
    HTML_EMIT(origjsonstr); HTML_EMIT(" -> ");
    HTML_EMIT("<textarea cols=\"150\" rows=\"10\"  name=\"jsonresult\">");
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
                        if ( 1 || juint(obj,"skip") == 0 )
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
                    else sprintf(buf,"<textarea cols=\"%d\" rows=\"%d\"  name=\"%s\" %s></textarea>",cols,rows,fieldname,cols == 1 ? "hidden" : "");
                    str = 0;//disp==0?jstr(obj,"disp"):disp;
                    sprintf(&retbuf[size],"<td>%s %s </td>\r\n",str!=0?str:fieldname,buf), size += strlen(&retbuf[size]);
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

char *iguana_htmlresponse(char *retbuf,int32_t bufsize,int32_t *remainsp,int32_t localaccess,char *retstr,int32_t freeflag)
{
    //static char *html = "<html> <head></head> <body> %s </body> </html>";
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
    if ( retstr == 0 || (json= cJSON_Parse(retstr)) == 0 )
        json = cJSON_CreateObject();
    jadd(json,"forms",formsjson);
    error = jstr(json,"error");
    result = jstr(json,"result");
    //printf("process.(%s)\n",jprint(formsjson,0));
    n = iguana_htmlgen(&retbuf[n],bufsize-n,result,error,json,"iguana",Currentjsonstr);
    free_json(json);
    /*if ( n == 0 )
    {
        n = (int32_t)(strlen(html) + strlen(retstr) + 1);
        sprintf(retbuf+strlen(retbuf),html,retstr);
    }*/
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
    printf("key.(%s) value.(%s)\n",key,value);
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

char *SuperNET_rpcparse(struct supernet_info *myinfo,char *retbuf,int32_t bufsize,int32_t *jsonflagp,int32_t *postflagp,char *urlstr,char *remoteaddr)
{
    cJSON *tokens,*argjson,*json = 0; char symbol[16],urlmethod[16],*data,url[1024],*retstr,*token = 0; int32_t i,j,n;
    printf("rpcparse.(%s)\n",urlstr);
    for (i=0; i<sizeof(urlmethod)-1&&urlstr[i]!=0&&urlstr[i]!=' '; i++)
        urlmethod[i] = urlstr[i];
    urlmethod[i++] = 0;
    n = i;
    printf("URLMETHOD.(%s)\n",urlmethod);
    *postflagp = (strcmp(urlmethod,"POST") == 0);
    for (i=0; i<sizeof(url)-1&&urlstr[n+i]!=0&&urlstr[n+i]!=' '; i++)
        url[i] = urlstr[n+i];
    url[i++] = 0;
    n += i;
    j = i = 0;
    if ( strncmp(&url[i],"/api",strlen("/api")) == 0 )
    {
        *jsonflagp = 1;
        i += strlen("/api");
    } else *jsonflagp = 0;
    if ( strncmp(&url[i],"/bitmap",strlen("/bitmap")) == 0 )
    {
        i += strlen("/bitmap");
        *jsonflagp = 2;
        if ( url[i] == '/' )
            i++;
        iguana_bitmap(retbuf,bufsize,&url[i]);
        return(retbuf);
    }
    printf("URL.(%s)\n",url);
    if ( strcmp(url,"/favicon.ico") == 0 )
    {
        *jsonflagp = -1;
        return(0);
    }
    if ( url[i] != '/' )
        token = url;
    tokens = cJSON_CreateArray();
    for (; url[i]!=0; i++)
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
                        if ( strcmp(jstri(tokens,i),"coin") == 0 && strlen(jstri(tokens,i+1)) < 8 )
                        {
                            strcpy(symbol,jstri(tokens,i+1));
                            touppercase(symbol);
                            jaddstr(argjson,jstri(tokens,i),symbol);
                        } else jaddstr(argjson,jstri(tokens,i),jstri(tokens,i+1));
                        i++;
                    }
                }
            }
        }
        if ( jstr(argjson,"method") == 0 )
        {
            free_json(argjson);
            return(0);
        }
        retstr = SuperNET_JSON(myinfo,argjson,remoteaddr);
        free_json(argjson);
        //printf("(%s) -> (%s) postflag.%d (%s)\n",urlstr,cJSON_Print(json),*postflagp,retstr);
        return(retstr);
    }
    return(clonestr("{\"error\":\"couldnt process packet\"}"));
}

void iguana_rpcloop(void *args)
{
    struct supernet_info *myinfo = args;
    int32_t recvlen,bindsock,postflag,sock,remains,numsent,jsonflag,len; socklen_t clilen;
    char remoteaddr[64],jsonbuf[8192],*buf,*retstr,*space;//,*retbuf; ,n,i,m
    struct sockaddr_in cli_addr; uint32_t ipbits,i,size = IGUANA_WIDTH*IGUANA_HEIGHT*16 + 512; uint16_t port;
    port = IGUANA_RPCPORT;
    bindsock = iguana_socket(1,"127.0.0.1",port);
    printf("iguana_rpcloop 127.0.0.1:%d bind sock.%d\n",port,bindsock);
    space = calloc(1,size);
    while ( bindsock >= 0 )
    {
        clilen = sizeof(cli_addr);
        //printf("ACCEPT (%s:%d) on sock.%d\n","127.0.0.1",port,bindsock);
        sock = accept(bindsock,(struct sockaddr *)&cli_addr,&clilen);
        if ( sock < 0 )
        {
            //printf("iguana_rpcloop ERROR on accept usock.%d\n",sock);
            continue;
        }
        memcpy(&ipbits,&cli_addr.sin_addr.s_addr,sizeof(ipbits));
        expand_ipbits(remoteaddr,ipbits);
        //printf("RPC.%d for %x (%s)\n",sock,ipbits,ipaddr);
        //printf("%p got.(%s) from %s | usock.%d ready.%u dead.%u\n",addr,H.command,addr->ipaddr,addr->usock,addr->ready,addr->dead);
        memset(jsonbuf,0,sizeof(jsonbuf));
        remains = (int32_t)(sizeof(jsonbuf) - 1);
        buf = jsonbuf;
        recvlen = 0;
        retstr = 0;
        while ( remains > 0 )
        {
            if ( (len= (int32_t)recv(sock,buf,remains,0)) < 0 )
            {
                if ( errno == EAGAIN )
                {
                    printf("EAGAIN for len %d, remains.%d\n",len,remains);
                    usleep(10000);
                }
                break;
            }
            else
            {
                if ( len > 0 )
                {
                    remains -= len;
                    recvlen += len;
                    buf = &buf[len];
                    retstr = SuperNET_rpcparse(myinfo,space,size,&jsonflag,&postflag,jsonbuf,remoteaddr);
                    break;
                } else usleep(10000);
                //printf("got.(%s) %d remains.%d of total.%d\n",jsonbuf,recvlen,remains,len);
                //retstr = iguana_rpcparse(space,size,&postflag,jsonbuf);
                break;
            }
        }
        if ( retstr == 0 )
            retstr = iguana_htmlresponse(space,size,&remains,1,retstr,retstr != space);
        if ( retstr != 0 )
        {
            i = 0;
            if ( 0 && postflag == 0 )
                retstr = iguana_htmlresponse(space,size,&remains,1,retstr,retstr != space);
            else remains = (int32_t)strlen(retstr);
            //printf("POSTFLAG.%d\n",postflag);
            //printf("RETBUF.(%s)\n",retstr);
            while ( remains > 0 )
            {
                if ( (numsent= (int32_t)send(sock,&retstr[i],remains,MSG_NOSIGNAL)) < 0 )
                {
                    if ( errno != EAGAIN && errno != EWOULDBLOCK )
                    {
                        //printf("%s: %s numsent.%d vs remains.%d len.%d errno.%d (%s) usock.%d\n",retstr,ipaddr,numsent,remains,recvlen,errno,strerror(errno),sock);
                        break;
                    }
                }
                else if ( remains > 0 )
                {
                    remains -= numsent;
                    i += numsent;
                    if ( remains > 0 )
                        printf("iguana sent.%d remains.%d of len.%d\n",numsent,remains,recvlen);
                }
            }
            if ( retstr != space)
                free(retstr);
        }
        if ( Currentjsonstr[0] != 0 )
            strcpy(Prevjsonstr,Currentjsonstr);
        Currentjsonstr[0] = 0;
        //printf("done response sock.%d\n",sock);
        closesocket(sock);
    }
}