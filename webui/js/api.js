/*!
 * Iguana api config
 *
 */

var server = {
  "protocol": "http://",
  "ip": "localhost",
  "port": "7778"
};
var apiRoutes = {
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
};
var newCoinConf = {
  "btc": {
    "services": 129,
    "portp2p": 8334
  },
  "btcd": {
    "services": 0,
    "portp2p": 14631
  }
};

function getServerUrl() {
  return server.protocol + server.ip + ":" + server.port + "/api/";
}

function walletLogin(passphrase) {
  var result = false;

  $.ajax({
    url: getServerUrl() + apiRoutes.bitcoinRPC.walletPassphrase + "?password=" + passphrase + "&timeout=300",
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

function walletCreate(passphrase) {
  var result = false;

  $.ajax({
    url: getServerUrl() + apiRoutes.bitcoinRPC.encryptWallet + "?passphrase=" + passphrase,
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

function listTransactions(account) {
  var result = false;

  $.ajax({
    url: getServerUrl() + apiRoutes.bitcoinRPC.listTransactions + "?account=" + account,
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

function getTransaction(txid) {
  var result = false;

  $.ajax({
    url: getServerUrl() + apiRoutes.bitcoinRPC.getTransaction + "?txid=" + txid,
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

function getBalance(account) {
  var result = false;

  $.ajax({
    url: getServerUrl() + apiRoutes.bitcoinRPC.getBalance + "?account=" + account,
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

function addCoin(coin) {
  var result = false;

  $.ajax({
    url: getServerUrl() + apiRoutes.iguana.addCoin + "?newcoin=" + coin.toUpperCase() + "&services=" + newCoinConf[coin].services + "&portp2p=" + newCoinConf[coin].portp2p,
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
function getIguanaRate(quote) {
  var result = false;
  var quoteComponents = quote.split("/");

  $.ajax({
    url: getServerUrl() + apiRoutes.iguana.rate + "?base=" + quoteComponents[0] + "&rel=" +quoteComponents[1],
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
function getExternalRate(quote) {
  var result = false;
  quote = quote.toLowerCase().replace("/", "-");

  // "https://www.google.com/finance/info?q=CURRENCY%3aBTCUSD"
  //_response = _response.replace("// [", "").replace("]", "");
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