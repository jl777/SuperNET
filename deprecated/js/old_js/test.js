var pages = [
    {value:"InstantDEX", width:100,"click":InstantDEX},
    { view:"button", value:"pangea", width:100,"click":Pangea },
    { view:"button", value:"Jumblr", width:100,"click":Jumblr },
    { view:"button", value:"Atomic", width:100,"click":Atomic },
    { view:"button", value:"MGW", width:100,"click":MGW },
    { view:"button", value:"PAX", width:100,"click":PAX },
    { view:"button", value:"Wallet", width:100,"click":Wallet },
    { view:"button", value:"Debug", width:100,"click":debuglog }
];


var SPNAPI = (function(SPNAPI, $, undefined) {

    SPNAPI.methods.instantDEX = [
        {"id":1,"method":"allorderbooks","base":"","rel":"","exchange":"","price":"","volume":""},
        {"id":2,"method":"allexchanges","base":"","rel":"","exchange":"","price":"","volume":""},
        {"id":2,"method":"openorders","base":"","rel":"","exchange":"","price":"","volume":""},
        {"id":3,"method":"orderbook","base":"base","rel":"rel","exchange":"active","price":"","volume":""},
        {"id":4,"method":"placeask","base":"base","rel":"rel","exchange":"active","price":"price","volume":"volume"},
        {"id":5,"method":"placebid","base":"base","rel":"rel","exchange":"active","price":"price","volume":"volume"},
        {"id":6,"method":"orderstatus","base":"","rel":"","exchange":"","price":"","volume":"","orderid":"orderid"},
        {"id":7,"method":"cancelorder","base":"","rel":"","exchange":"","price":"","volume":"","orderid":"orderid"},
        {"id":8,"method":"enablequotes","base":"base","rel":"rel","exchange":"exchange","price":"","volume":""},
        {"id":9,"method":"disablequotes","base":"base","rel":"rel","exchange":"exchange","price":"","volume":""},
        {"id":10,"method":"lottostats","base":"","rel":"","exchange":"","price":"","volume":""},
        {"id":11,"method":"tradehistory","base":"","rel":"","exchange":"","price":"","volume":""},
        {"id":12,"method":"balance","base":"","rel":"","exchange":"exchange","price":"","volume":""},
        {"id":13,"method":"peggyrates","base":"base","rel":"","exchange":"","price":"","volume":""}
    ];

    SPNAPI.methods.pangea = [
        {"id":1,"method":"start","base":"base","maxplayers":"maxplayers","bigblind":"bigblind","ante":"ante","hostrake":"hostrake"},
        {"id":2,"method":"status","tableid":"tableid"},
        {"id":3,"method":"turn","tableid":"tableid"},
        {"id":4,"method":"mode"},
        {"id":5,"method":"buyin","tableid":"tableid"},
        {"id":6,"method":"history","tableid":"tableid","handid":"handid"},
        {"id":7,"method":"rates","base":"base"},
        {"id":8,"method":"lobby"},
        {"id":9,"method":"tournaments"},
        {"id":10,"method":"rosetta","base":"base"}
    ];

    SPNAPI.methods.jumblr = [
        {"id":1,"method":"jumblr","base":"base","maxplayers":"maxplayers","bigblind":"bigblind","ante":"ante"},
        {"id":2,"method":"status","tableid":"tableid"}
    ];

    SPNAPI.methods.mgw =[
        {"id":1,"method":"MGW","base":"base","maxplayers":"maxplayers","bigblind":"bigblind","ante":"ante"},
        {"id":2,"method":"status","tableid":"tableid"}
    ];

    SPNAPI.methods.atomic = [
        {"id":1,"method":"atomic","base":"base","maxplayers":"maxplayers","bigblind":"bigblind","ante":"ante"},
        {"id":2,"method":"status","tableid":"tableid"}
    ];

    SPNAPI.methods.pax = [
        {"id":1,"method":"peggy","base":"base","maxplayers":"maxplayers","bigblind":"bigblind","ante":"ante"},
        {"id":2,"method":"status","tableid":"tableid"}
    ];

    SPNAPI.methods.wallet = [
        {"id":1,"method":"wallet","base":"base","maxplayers":"maxplayers","bigblind":"bigblind","ante":"ante"},
        {"id":2,"method":"status","tableid":"tableid"}
    ];


    return SPNAPI;
}(SPNAPI || {}, jQuery));



var api_request = function(agent)
{
    var jsonstr = '';//$$("apirequest").getValues().jsonstr;
    var base = $$("formA").getValues().base;
    var rel = $$("formB").getValues().rel;
    var exchange = $$("formC").getValues().exchange;
    var price = $$("formD").getValues().price;
    var volume = $$("formE").getValues().volume;
    var orderid = $$("formF").getValues().orderid;
    var method = $$("method").getValues().method;
    var request = '{"agent":"' + agent + '","method":"' + method + '","base":"' + base + '","rel":"' + rel + '","exchange":"' + exchange + '","price":"' + price + '","volume":"' + volume + '","orderid":"' + orderid + '"' + jsonstr + '}';
    return(request);
}

function submit_request(e)
{
    var request = $$("apirequest").getValues().jsonstr;
    postCall('SuperNET', request, function(jsonstr)
    {
        $$("debuglog").add({value:jsonstr},0);
        common.logMessage(jsonstr + '\n');
    });
}

function InstantDEX(e)
{
    $$('list').data.sync(Idata);
    request = api_request('InstantDEX');
    $$("submitstr").setValue(request);
    /*postCall('SuperNET', request, function(jsonstr)
     {
     $$("debuglog").add({value:jsonstr},0);
     common.logMessage(jsonstr + '\n');
     });*/
}

function Pangea(e)
{
    $$('list').data.sync(Pdata);
    request = api_request('pangea');
    $$("submitstr").setValue(request);
}

function Jumblr(e)
{
    $$('list').data.sync(Jdata);
    request = api_request('jumblr');
    $$("submitstr").setValue(request);
}

function MGW(e)
{
    $$('list').data.sync(Mdata);
    request = api_request('MGW');
    $$("submitstr").setValue(request);
}

function Atomic(e)
{
    $$('list').data.sync(Adata);
    request = api_request('atomic');
    $$("submitstr").setValue(request);
}

function PAX(e)
{
    $$('list').data.sync(Xdata);
    request = api_request('peggy');
    $$("submitstr").setValue(request);
}

function Wallet(e)
{
    $$('list').data.sync(Wdata);
    request = api_request('wallet');
    $$("submitstr").setValue(request);
}

var debug_on = 0;
function debuglog(e) {
    if ( debug_on == 0 )
    {
        $(".debuglog").show();
        debug_on = 1;
    }
    else
    {
        $(".debuglog").hide();
        debug_on = 0;
    }
}
