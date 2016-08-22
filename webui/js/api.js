/*!
 * Iguana api config
 *
 */

var apiProto = function() {};

var currentCoinPort = 0;

apiProto.prototype.getConf = function() {
  var conf = {
      "server": {
        "protocol": "http://",
        "ip": "localhost",
        "port": "7778"
      },
      "apiRoutes": {
        "bitcoinRPC" : {
          "walletPassphrase" : "bitcoinrpc/walletpassphrase", // params: password String, timeout Int
          "encryptWallet" : "bitcoinrpc/encryptwallet", // params: passphrase String
          "listTransactions": "bitcoinrpc/listtransactions", // params: account String
          "getTransaction": "bitcoinrpc/gettransaction", // params: txid String
          "getBalance": "bitcoinrpc/getbalance" // params: account String
        },
        "iguana": {
          "addCoin": "iguana/addcoin", // params newcoin, portp2p, services
          "rates": "iguana/rates", // params: coin/curency or currency/currency or coin/coin, variable length
          "rate": "iguana/rate" // params: base, rel e.g. base=BTC&rel=USD, !param values in CAPS!
        }
      },
      "newCoinConf": {
        "btc": {
          "services": 129,
          "portp2p": 8333
        },
        "btcd": {
          "services": 0,
          "portp2p": 14631
        }
      }
  };

  // coin port switch hook
  /*if (currentCoinPort !== 0)
    conf.server.port = conf.newCoinConf.[currentCoinPort].portp2p;*/

  return conf;
}

apiProto.prototype.getServerUrl = function() {
  return apiProto.prototype.getConf().server.protocol + apiProto.prototype.getConf().server.ip + ":" + apiProto.prototype.getConf().server.port + "/api/";
}

apiProto.prototype.walletLogin = function(passphrase, timeout) {
  var result = false;

  $.ajax({
    url: apiProto.prototype.getServerUrl() + apiProto.prototype.getConf().apiRoutes.bitcoinRPC.walletPassphrase + "?password=" + passphrase + "&timeout=" + timeout,
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
        result = response;
      } else {
        result = false;
      }
    }
  });

  return result;
}

apiProto.prototype.walletCreate = function(passphrase) {
  var result = false;

  $.ajax({
    url: apiProto.prototype.getServerUrl() + apiProto.prototype.getConf().apiRoutes.bitcoinRPC.encryptWallet + "?passphrase=" + passphrase,
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
        result = response;
      } else {
        result = false;
      }
    }
  });

  return result;
}

apiProto.prototype.listTransactions = function(account) {
  var result = false;

  $.ajax({
    url: apiProto.prototype.getServerUrl() + apiProto.prototype.getConf().apiRoutes.bitcoinRPC.listTransactions + "?account=" + account,
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
      if (response.result.length) {
        result = response.result;
      } else {
        result = false;
      }
    }
  });

  return result;
}

apiProto.prototype.getTransaction = function(txid) {
  var result = false;

  $.ajax({
    url: apiProto.prototype.getServerUrl() + apiProto.prototype.getConf().apiRoutes.bitcoinRPC.getTransaction + "?txid=" + txid,
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
      if (response.txid === txid) {
        result = response;
      } else {
        result = false;
      }
    }
  });

  return result;
}

apiProto.prototype.getBalance = function(account) {
  var result = false;

  $.ajax({
    url: apiProto.prototype.getServerUrl() + apiProto.prototype.getConf().apiRoutes.bitcoinRPC.getBalance + "?account=" + account,
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
      if (response.result) {
        result = response.result;
      } else {
        result = false;
      }
    }
  });

  return result;
}

apiProto.prototype.addCoin = function(coin) {
  var result = false;

  $.ajax({
    url: apiProto.prototype.getServerUrl() + apiProto.prototype.getConf().apiRoutes.iguana.addCoin + "?newcoin=" + coin.toUpperCase() + "&services=" + newCoinConf[coin].services + "&portp2p=" + newCoinConf[coin].portp2p,
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
    url: apiProto.prototype.getServerUrl() + apiProto.prototype.getConf().apiRoutes.iguana.rate + "?base=" + quoteComponents[0] + "&rel=" + quoteComponents[1],
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
// TODO: add secondary quote service
apiProto.prototype.getExternalRate = function(quote) {
  var result = false;
  quote = quote.toLowerCase().replace("/", "-");

  $.ajax({
    url: "https://www.cryptonator.com/api/full/" + quote,
    cache: false,
    dataType: "text",
    async: false
  })
  .done(function(_response) {
    var response = $.parseJSON(_response);

    if (response && response.ticker.price) {
      result = response.ticker.price;
    } else {
      result = false;
    }
  });

  return result;
}

/*
  TODO: figure out why POST is failing
function getConversionRates(_quotes) {
  var result = false;

  $.post(getServerUrl() + apiRoutes.iguana.rates, {"quotes": _quotes}, function(response) {
    console.log(response);
  });
}
*/