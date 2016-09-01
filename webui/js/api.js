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
    "encryptWallet" : "bitcoinrpc/encryptwallet" // params: passphrase String
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
        result = true;
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
        result = true;
      } else {
        result = false;
      }
    }
  });

  return result;
}