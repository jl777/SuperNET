/*!
 * Iguana api config
 *
 */

// TODO: 1) add response handler
//       2) generalize get/post functions into one
//       3) add general error handler, e.g. coin is not added, wallet is locked etc
//       4) add localstorage hook on testPort success
//      (?) refactor conf into a singleton obj

// note(!): p2p may vary depending on a coin
// some coins put rpc at the p2p port+1 others port-1
// if no portp2p is specified iguana picks default port
// possible solution: check adjacent ports to verify which one is responding

var apiProto = function() {};

var activeCoin,
    portsTested = false,
    isIguana = false,
    proxy = "http://localhost:1337/"; // https://github.com/gr2m/CORS-Proxy

apiProto.prototype.getConf = function(discardCoinSpecificPort) {
  var conf = {
      "server": {
        "protocol": "http://",
        "ip": "localhost",
        "iguanaPort": "7778"
      },
      "apiRoutes": {
        "bitcoinRPC" : {
          "walletPassphrase" : "bitcoinrpc/walletpassphrase", // params: password String, timeout Int
          "encryptWallet" : "bitcoinrpc/encryptwallet", // params: passphrase String
          "listTransactions": "bitcoinrpc/listtransactions", // params: account String, count: default is 1
          "getTransaction": "bitcoinrpc/gettransaction", // params: txid String
          "getBalance": "bitcoinrpc/getbalance" // params: account String
        },
        "iguana": {
          "addCoin": "iguana/addcoin", // params newcoin, portp2p, services
          "rates": "iguana/rates", // params: coin/curency or currency/currency or coin/coin, variable length
          "rate": "iguana/rate" // params: base, rel e.g. base=BTC&rel=USD, !param values in CAPS!
        }
      },
      "coins": {
        "btc": {
          "services": 129,
          "portp2p": 8332,
          "user": "pbca26", // add your rpc pair here
          "pass": "pbca26"
        },
        "btcd": {
          "services": 0,
          "portp2p": 14632,
          "user": "user", // add your rpc pair here
          "pass": "pass"
        }
      }
  };

  //if (!portsTested) apiProto.prototype.testConnection();

  // coin port switch hook
  if (activeCoin && !discardCoinSpecificPort)
    conf.server.port = conf.coins[activeCoin].portp2p;
  else
    conf.server.port = conf.server.iguanaPort;

  // bitcoind rpc hook
  // if rpc user and password are supplied it should communicate with bitcoin/altcoin
  /*if (activeCoin && !iguanaEnv && conf.coins[activeCoin].user && conf.coins[activeCoin].pass) // inject user:pass@
    conf.server.ip = conf.coins[activeCoin].user + ":" + conf.coins[activeCoin].pass + "@" + conf.server.ip;*/

  //console.log(conf.server);

  return conf;
}

// test must be hooked to initial gui start or addcoin method
// test 1 port for a single coin
apiProto.prototype.testCoinPorts = function() {
  var result = false; /*,
      repeat = 3; // check default port, port+1, port-1*/

  $.each(apiProto.prototype.getConf().coins, function(index, conf) {
    var fullUrl = isIguana ? apiProto.prototype.getConf().server.protocol + apiProto.prototype.getConf().server.ip + ":" + conf.portp2p + "/api/bitcoinrpc/getinfo" : proxy + apiProto.prototype.getConf().server.ip + ":" + conf.portp2p;
    var postData = isIguana ? "" : "{ \"agent\": \"bitcoinrpc\", \"method\": \"getinfo\", \"params\": [] }";
    var postAuthHeaders = isIguana ? "" : { "Authorization": "Basic " + btoa(conf.user + ":" + conf.pass) };

    $.ajax({
      url: fullUrl,
      cache: false,
      async: false,
      dataType: "json",
      type: "POST",
      //contentType: 'application/json',
      data: postData,
      headers: postAuthHeaders,
      success: function (response) {
        console.log(response);
        if (response.result.walletversion || response.result === "success") {
          console.log('portp2p con test passed');
          console.log(index + ' daemon is detected');
          activeCoin = index;
        }
        if (response.status)
          if (response.status.indexOf("BTCD.RT0 ") > -1) console.log("RT is not ready yet!");
      },
      error: function (response) {
        console.log(response.responseText);
      }
    });
  });

  return result;
}

// check if iguana is running
apiProto.prototype.testConnection = function() {
  var result = false;

  // test if iguana is running
  var defaultIguanaServerUrl = apiProto.prototype.getConf().server.protocol + apiProto.prototype.getConf().server.ip + ":" + apiProto.prototype.getConf().server.iguanaPort;
  console.log(defaultIguanaServerUrl + "/api/iguana/getconnectioncount");
  $.ajax({
    url: defaultIguanaServerUrl + "/api/iguana/getconnectioncount",
    cache: false,
    dataType: "text",
    async: false,
    type: 'GET',
    success: function (response) {
      // iguana env
      console.log('iguana is detected');
      isIguana = true;
      apiProto.prototype.testCoinPorts();
    },
    error: function (response) {
      // non-iguana env
      console.log('running non-iguana env');
      apiProto.prototype.testCoinPorts();
    }
  });

  portsTested = true;
}

apiProto.prototype.getServerUrl = function(discardCoinSpecificPort) {
  return apiProto.prototype.getConf().server.protocol + apiProto.prototype.getConf().server.ip + ":" + apiProto.prototype.getConf(discardCoinSpecificPort).server.port + "/api/";
}

apiProto.prototype.walletLogin = function(passphrase, timeout) {
  var result = false;

  var fullUrl = isIguana ? apiProto.prototype.getConf().server.protocol + apiProto.prototype.getConf().server.ip + ":" + apiProto.prototype.getConf().server.port + "/api/bitcoinrpc/walletpassphrase" : proxy + apiProto.prototype.getConf().server.ip + ":" + apiProto.prototype.getConf().server.port;
  var postData = "{ \"agent\": \"bitcoinrpc\", \"method\": \"walletpassphrase\", \"params\": [\"" + passphrase + "\", " + timeout + "] }";
  var postAuthHeaders = isIguana ? "" : { "Authorization": "Basic " + btoa(apiProto.prototype.getConf().coins[activeCoin].user + ":" + apiProto.prototype.getConf().coins[activeCoin].pass) };

  $.ajax({
    //url: apiProto.prototype.getServerUrl() + apiProto.prototype.getConf().apiRoutes.bitcoinRPC.walletPassphrase + "?password=" + passphrase + "&timeout=" + timeout,
    url: fullUrl,
    cache: false,
    async: false,
    dataType: "json",
    type: "POST",
    //contentType: 'application/json',
    data: postData,
    headers: postAuthHeaders,
    success: function(response) {
      /*if (response.responseText)
        console.log(response.responseText);
      else*/
      console.log(response);
      result = true;
    },
    error: function(response) {
      if (response.responseText) {
        if (response.responseText.indexOf("Error: Wallet is already unlocked, use walletlock first if need to change unlock settings.") > -1)
          result = true;
        console.log(response.responseText);
      } else {
        console.log(response.error);
      }
    }
  });

  return result;
}

apiProto.prototype.walletCreate = function(passphrase) {
  var result = false;

  var fullUrl = isIguana ? apiProto.prototype.getConf().server.protocol + apiProto.prototype.getConf().server.ip + ":" + apiProto.prototype.getConf().server.port + "/api/bitcoinrpc/encryptwallet" : proxy + apiProto.prototype.getConf().server.ip + ":" + apiProto.prototype.getConf().server.port;
  var postData = "{ \"agent\": \"bitcoinrpc\", \"method\": \"encryptwallet\", \"params\": [\"" + passphrase + "\"] }";
  var postAuthHeaders = isIguana ? "" : { "Authorization": "Basic " + btoa(apiProto.prototype.getConf().coins[activeCoin].user + ":" + apiProto.prototype.getConf().coins[activeCoin].pass) };

  $.ajax({
    url: fullUrl,
    cache: false,
    async: false,
    dataType: "json",
    type: "POST",
    //contentType: 'application/json',
    data: postData,
    headers: postAuthHeaders
  })
  .done(function(_response) {
    console.log(_response);
    if (_response.result) {
      // non-iguana
      if (_response.result) {
        result = _response.result;
      } else {
        result = false;
      }
    } else {
      // iguana
      var response = $.parseJSON(_response);

      if (response.error) {
        // do something
        console.log("error: " + response.error);
        result = false;
      } else {
        if (response.result === "success") {
          result = response;
        } else {
          result = false;
        }
      }
    }
  });

  return result;
}

apiProto.prototype.listTransactions = function(account) {
  var result = false;

  var fullUrl = isIguana ? apiProto.prototype.getConf().server.protocol + apiProto.prototype.getConf().server.ip + ":" + apiProto.prototype.getConf().server.port + "/api/bitcoinrpc/listtransactions" : proxy + apiProto.prototype.getConf().server.ip + ":" + apiProto.prototype.getConf().server.port;
  var postData = "{ \"agent\": \"bitcoinrpc\", \"method\": \"listtransactions\", \"params\": [\"" + account + "\", 20] }";
  var postAuthHeaders = isIguana ? "" : { "Authorization": "Basic " + btoa(apiProto.prototype.getConf().coins[activeCoin].user + ":" + apiProto.prototype.getConf().coins[activeCoin].pass) };

  $.ajax({
    //url: apiProto.prototype.getServerUrl() + apiProto.prototype.getConf().apiRoutes.bitcoinRPC.listTransactions + "?account=" + account + "&count=20",
    url: fullUrl,
    cache: false,
    async: false,
    dataType: "json",
    type: "POST",
    //contentType: 'application/json',
    data: postData,
    headers: postAuthHeaders
  })
  .done(function(_response) {
    console.log(_response);
    if (_response.result) {
      // non-iguana
      if (_response.result.length) {
        result = _response.result;
      } else {
        result = false;
      }
    } else {
      // iguana
      var response = $.parseJSON(_response);

      if (response.error) {
        // do something
        console.log("error: " + response.error);
        result = false;
      } else {
        if (response.result.length) {
          result = response.result;
        } else {
          result = false;
        }
      }
    }
  });

  return result;
}

apiProto.prototype.getTransaction = function(txid) {
  var result = false;

  var fullUrl = isIguana ? apiProto.prototype.getConf().server.protocol + apiProto.prototype.getConf().server.ip + ":" + apiProto.prototype.getConf().server.port + "/api/bitcoinrpc/gettransaction" : proxy + apiProto.prototype.getConf().server.ip + ":" + apiProto.prototype.getConf().server.port;
  var postData = "{ \"agent\": \"bitcoinrpc\", \"method\": \"gettransaction\", \"params\": [\"" + txid + "\"] }";
  var postAuthHeaders = isIguana ? "" : { "Authorization": "Basic " + btoa(apiProto.prototype.getConf().coins[activeCoin].user + ":" + apiProto.prototype.getConf().coins[activeCoin].pass) };

  $.ajax({
    //url: apiProto.prototype.getServerUrl() + apiProto.prototype.getConf().apiRoutes.bitcoinRPC.listTransactions + "?account=" + account + "&count=20",
    url: fullUrl,
    cache: false,
    async: false,
    dataType: "json",
    type: "POST",
    //contentType: 'application/json',
    data: postData,
    headers: postAuthHeaders
  })
  .done(function(_response) {
    if (_response.result) {
      // non-iguana
      if (_response.result) {
        result = _response.result;
      } else {
        result = false;
      }
    } else {
      // iguana
      var response = _response;

      if (response.error) {
        // do something
        console.log("error: " + response.error);
        result = false;
      } else {
        if (response.txid) {
          result = response;
        } else {
          result = false;
        }
      }
    }
  });

  return result;
}

apiProto.prototype.getBalance = function(account) {
  var result = false;
  var fullUrl = isIguana ? apiProto.prototype.getConf().server.protocol + apiProto.prototype.getConf().server.ip + ":" + apiProto.prototype.getConf().server.port + "/api/bitcoinrpc/getbalance" : proxy + apiProto.prototype.getConf().server.ip + ":" + apiProto.prototype.getConf().server.port;
  var postData = "{ \"agent\": \"bitcoinrpc\", \"method\": \"getbalance\", \"params\": [\"" + account + "\"] }";
  var postAuthHeaders = isIguana ? "" : { "Authorization": "Basic " + btoa(apiProto.prototype.getConf().coins[activeCoin].user + ":" + apiProto.prototype.getConf().coins[activeCoin].pass) };

  $.ajax({
    //url: apiProto.prototype.getServerUrl() + apiProto.prototype.getConf().apiRoutes.bitcoinRPC.listTransactions + "?account=" + account + "&count=20",
    url: fullUrl,
    cache: false,
    async: false,
    dataType: "json",
    type: "POST",
    //contentType: 'application/json',
    data: postData,
    headers: postAuthHeaders
  })
  .done(function(_response) {
    if (_response.result) {
      // non-iguana
      result = _response.result;
    } else {
      // iguana
      var response = $.parseJSON(_response);

      if (response.error) {
        // do something
        console.log("error: " + response.error);
        result = false;
      } else {
        if (response) {
          result = response;
        } else {
          result = false;
        }
      }
    }
  });

  return result;
}

apiProto.prototype.addCoin = function(coin) {
  var result = false;

  $.ajax({
    url: apiProto.prototype.getServerUrl(true) + apiProto.prototype.getConf().apiRoutes.iguana.addCoin + "?newcoin=" + coin.toUpperCase() + "&services=" + newCoinConf[coin].services + "&portp2p=" + newCoinConf[coin].portp2p,
    cache: false,
    dataType: "text",
    async: false
  })
  .done(function(_response) {
    var response = $.parseJSON(_response);

    if (response.error) {
      // do something
      console.log("error: " + response.error);
      result = false;
    } else {
      if (response.result === "coin added" || response.result === "coin already there") {
        result = response;
      } else {
        result = false;
      }
    }
  });

  return result;
}

/* !requires the latest iguana build! */
apiProto.prototype.getIguanaRate = function(quote) {
  var result = false;
  var quoteComponents = quote.split("/");

  $.ajax({
    url: apiProto.prototype.getServerUrl(true) + apiProto.prototype.getConf().apiRoutes.iguana.rate + "?base=" + quoteComponents[0] + "&rel=" + quoteComponents[1],
    cache: false,
    dataType: "text",
    async: false
  })
  .done(function(_response) {
    var response = $.parseJSON(_response);

    if (response.error) {
      // do something
      console.log("error: " + response.error);
      result = false;
    } else {
      if (response.result === "success") {
        result = response.quote;
      } else {
        result = false;
      }
    }
  });

  return result;
}

// get a quote form an external source
// TODO: 1) add secondary quote service
//       2) add fallback in case both services fail/take too long to respond
// alt: https://poloniex.com/public?command=returnTicker
// upd 02.09.2016, cryptonator is unstable, look for substitution
apiProto.prototype.getExternalRate = function(quote) {
  var result = false,
      firstSourceFailed = false,
      quoteComponents = quote.split("/");
  quote = quote.toLowerCase().replace("/", "-");

  $.ajax({
    url: "https://www.cryptonator.com/api/full/" + quote,
    cache: false,
    dataType: "text",
    async: false,
    success: function(_response) {
      var response = $.parseJSON(_response);

      if (response && response.ticker.price) {
        result = response.ticker.price;
      } else {
        result = false;
      }
    },
    error: function(response) {
      console.log('falling back to ext service #2');
      firstSourceFailed = true;
    }
  });
  if (firstSourceFailed)
    $.ajax({
      url: "https://min-api.cryptocompare.com/data/price?fsym=" + quoteComponents[0] + "&tsyms=" + quoteComponents[1],
      cache: false,
      dataType: "text",
      async: false,
      success: function(_response) {
        var response = $.parseJSON(_response);

        if (response && response[quoteComponents[1]]) {
          result = response[quoteComponents[1]];
        } else {
          result = false;
        }
      },
      error: function(response) {
        // non-iguana env
        console.log('both services failed to respond');
      }
    });

  return result;
}

apiProto.prototype.testConnection(); // run this everytime a page is (re)loaded