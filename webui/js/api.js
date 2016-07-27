/*!
 * Iguana api config
 *
 */

var protocol = "http://";
var serverName = "localhost";
var serverPort = "7778";
var apiRoutes = {
  "bitcoinRPC" : {
    "walletPassphrase" : "bitcoinrpc/walletpassphrase"
  }
};

function getServerUrl() {
  return protocol + serverName + ":" + serverPort + '/api/';
}
function walletLogin(passphrase) {
  var result = false;

  $.ajax({
    url: getServerUrl() + apiRoutes.bitcoinRPC.walletPassphrase + "?password=" + passphrase + "&timeout=300",
    cache: false,
    dataType: "text",
    async: false
  })
  .done(function(_response){
    var response = $.parseJSON(_response);
    if (response.error) {
      // do something
      console.log('error: ' + response.error);
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