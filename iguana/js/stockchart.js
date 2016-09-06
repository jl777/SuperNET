var httpresult;

function http_handler() {
    if (this.status == 200 && this.responseText != null) {
        alert(this.responseText);
        httpresult = this.responseText;
    }
}

function httpGet(url) {
    var client;
    if (window.XMLHttpRequest) {
        client = new XMLHttpRequest();
    } else {
        client = new ActiveXObject('Microsoft.XMLHTTP');
    }
    client.onload = http_handler;
    client.open('GET', url);
    client.send();
}

AmCharts.ready(function() {
    createStockChart();
});
var interval, BASE = "BTCD",
    REL = "BTC";

function createStockChart() {
    var chartData = [];
    var chart = AmCharts.makeChart("chartdiv", {
        "type": "serial",
        "theme": "dark",
        "valueAxes": [{
            "title": "BTC",
            "id": "vert",
            "axisAlpha": 0,
            "dashLength": 1,
            "position": "left"
        }, {
            "id": "horiz",
            "axisAlpha": 0,
            "dashLength": 1,
            "position": "bottom",
            "labelFunction": function(value) {
                var date = new Date(value);
                return AmCharts.formatDate(date, "MMM DD HH:NN:SS");
            }
        }],
        "graphs": [{
            "id": "g1",
            "lineColor": "#00FFFF",
            "bullet": "round",
            "valueField": "bid",
            "balloonText": "[[category]] [[h]]:[[m]]:[[s]] account:[[offerer]] id:[[orderid]] volume:[[volume]] bid:[[bid]]"
        }, {
            "id": "g2",
            "lineColor": "#FF8800",
            "bullet": "round",
            "valueField": "ask",
            "balloonText": "[[category]] [[h]]:[[m]]:[[s]] account:[[offerer]] id:[[orderid]] volume:[[volume]] ask:[[ask]]"
        }],
        "categoryField": "date",
        "categoryAxis": {
            "parseDates": true,
            "equalSpacing": true,
            "dashLength": 1,
            "minorGridEnabled": true
        },
        "chartScrollbar": {},
        "chartCursor": {},
        "dataProvider": chartData
    });

    var startButton = document.getElementById('start');
    var endButton = document.getElementById('stop');
    var buyButton = document.getElementById('buy');
    var sellButton = document.getElementById('sell');
    /*
    var BTCbutton = document.getElementById('BTC');
    var CNYbutton = document.getElementById('CNY');
    var USDbutton = document.getElementById('USD');
    var EURbutton = document.getElementById('EUR');
    var JPYbutton = document.getElementById('JPY');
    var GBPbutton = document.getElementById('GBP');
    var AUDbutton = document.getElementById('AUD');
    var CADbutton = document.getElementById('CAD');
    var CHFbutton = document.getElementById('CHF');
    var NZDbutton = document.getElementById('NZD');
     
     USDbutton.addEventListener('click', USDrel);
     EURbutton.addEventListener('click', EURrel);
     JPYbutton.addEventListener('click', JPYrel);
     GBPbutton.addEventListener('click', GBPrel);
     AUDbutton.addEventListener('click', AUDrel);
     CADbutton.addEventListener('click', CADrel);
     CHFbutton.addEventListener('click', CHFrel);
     NZDbutton.addEventListener('click', NZDrel);
     CNYbutton.addEventListener('click', CNYrel);
     BTCbutton.addEventListener('click', BTCrel);
    */

    var BTCDbutton = document.getElementById('BTCD');
    var VPNbutton = document.getElementById('VPN');
    var VRCbutton = document.getElementById('VRC');
    var SYSbutton = document.getElementById('SYS');
    var SuperNETbutton = document.getElementById('SuperNET');
    var crypto777button = document.getElementById('crypto777');
    var pangeabutton = document.getElementById('Pangea');
    var InstantDEXbutton = document.getElementById('InstantDEX');
    var Tradebotsbutton = document.getElementById('Tradebots');
    var NXTprivacybutton = document.getElementById('NXTprivacy');


    startButton.addEventListener('click', startDemo);
    endButton.addEventListener('click', endDemo);
    buyButton.addEventListener('click', buyaction);
    sellButton.addEventListener('click', sellaction);

    BTCDbutton.addEventListener('click', BTCDbase);
    VPNbutton.addEventListener('click', VPNbase);
    SYSbutton.addEventListener('click', SYSbase);
    SuperNETbutton.addEventListener('click', SuperNETbase);
    crypto777button.addEventListener('click', crypto777base);
    pangeabutton.addEventListener('click', Pangeabase);
    InstantDEXbutton.addEventListener('click', InstantDEXbase);
    Tradebotsbutton.addEventListener('click', Tradebotsbase);
    NXTprivacybutton.addEventListener('click', NXTprivacybase);

    function changebase(newbase) {
        BASE = newbase;
        if (chartData.length > 0) {
            chartData.splice(0, chartData.length);
            chart.validateData();
        }
    }

    function BTCDbase() {
        changebase("BTCD");
    }

    function VPNbase() {
        changebase("VPN");
    }

    function SYSbase() {
        changebase("SYS");
    }

    function SuperNETbase() {
        changebase("SuperNET");
    }

    function crypto777base() {
        changebase("crypto777");
    }

    function Pangeabase() {
        changebase("Pangea");
    }

    function InstantDEXbase() {
        changebase("InstantDEX");
    }

    function Tradebotsbase() {
        changebase("Tradebots");
    }

    function NXTprivacybase() {
        changebase("NXTprivacy");
    }

    function USDrel() {
        REL = "USD";
    }

    function EURrel() {
        REL = "EUR";
    }

    function JPYrel() {
        REL = "JPY";
    }

    function GBPrel() {
        REL = "GBP";
    }

    function AUDrel() {
        REL = "AUD";
    }

    function CADrel() {
        REL = "CAD";
    }

    function CHFrel() {
        REL = "CHF";
    }

    function NZDrel() {
        REL = "NZD";
    }

    function CNYrel() {
        REL = "CNY";
    }

    function BTCrel() {
        REL = "CNY";
    }

    function startDemo() {
        startButton.disabled = "disabled";
        endButton.disabled = "";
        interval = setInterval(getDataFromServer, 1000);
    }

    function endDemo() {
        startButton.disabled = "";
        endButton.disabled = "disabled";
        clearInterval(interval);
    }

    function buyaction() {
        alert("need to do market buy");
    }

    function sellaction() {
        alert("need to do market sell");
    }

    function getDataFromServer() {
        var i, newData = [];
        var request = '{"agent":"InstantDEX","method":"events","base":"' + BASE + '","rel":"' + REL + '"}';
        SPNAPI.makeRequest(request,
            function(request, response) {
                newData = JSON.parse(response);
                if (newData.length > 0) {
                    alert(response);
                    chartData.push.apply(chartData, newData);
                    if (chartData.length > 50)
                        chartData.splice(0, chartData.length - 50);
                    chart.validateData(); //call to redraw the chart with new data
                }
            });
        // newData = JSON.parse("[{\"h\":14,\"m\":44,\"s\":32,\"date\":1407877200000,\"bid\":30,\"ask\":35},{\"date\":1407877200000,\"bid\":40,\"ask\":44},{\"date\":1407877200000,\"bid\":49,\"ask\":45},{\"date\":1407877200000,\"ask\":28},{\"date\":1407877200000,\"ask\":52}]");
    }
}