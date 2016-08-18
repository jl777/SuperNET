/*!
 * Iguana dashboard
 *
 */

 var defaultCurrency = "USD",
    defaultCoin = "BTCD";
    defaultCoinValue = 0,
    defaultCurrencyValue = 0,
    coinToCurrencyRate = 0,
    defaultAccount = "*", // note: change to a specific account name if needed
    coinsSelectedByUser = []
    dashboardUpdateTimout = 15; // sec

var availableCoinsToAdd = [ // temp, only for demo purposes
  { id: "btc", name: "Bitcoin", color: "orange" },
  { id: "btcd", name: "Bitcoin D.", color: "breeze" },
  { id: "ltc", name: "Litecoin", color: "yellow" },
  { id: "nxt", name: "NXT", color: "light-blue" },
  { id: "nmc", name: "Namecoin", color: "orange" },
  { id: "unity", name: "SuperNET", color: "breeze" }
];

$(document).ready(function() {
  updateRates();
  $(".account-coins-repeater").html(constructAccountCoinRepeater());
  $(".transactions-list-repeater").html(constructTransactionUnitRepeater());
  updateTotalBalance();
  updateTransactionUnitBalance();
  updateDashboardView(dashboardUpdateTimout);

  $(".top-menu .item").click(function() {
    $(".top-menu .item").each(function(index, item) {
      $(this).removeClass("active");
    });

    $(this).addClass("active");
    // $(this).attr("data-url")
    // TODO: add rounting
  });

  $(".lnk-logout").click(function() {
    // TODO: add logout
  });

  $(".btn-add-coin,.btn-close").click(function() {
    toggleModalWindow("add-new-coin-form", 300);
    coinsSelectedByUser = [];
    $(".supported-coins-repeater").html(constructCoinRepeater());
    bindClickInCoinRepeater();
  });
  $(".btn-next").click(function() {
    toggleModalWindow("add-new-coin-form", 300);
    coinsSelectedByUser = reindexAssocArray(coinsSelectedByUser);
    $(".account-coins-repeater").append(constructAccountCoinRepeater());
    bindClickInAccountCoinRepeater();
    updateTotalBalance();
  });

  bindCoinRepeaterSearch();
});

var coinRepeaterTemplate = "<div class=\"coin\" data-coin-id=\"{{ coin_id }}\">" +
                              "<i class=\"icon cc {{ id }}-alt col-{{ color }}\"></i>" +
                              "<div class=\"name\">{{ name }}</div>" +
                           "</div>";

function updateRates(coin, currency) {
  if (!coin) coin = defaultCoin;
  if (!currency) currency = defaultCurrency;
  coinToCurrencyRate = getIguanaRate(coin + "/" + currency);
  // graceful fallback
  // if iguana is not present get a quote form external source
  if (!coinToCurrencyRate || coinToCurrencyRate === 0) coinToCurrencyRate = getExternalRate(coin + "/" + currency);
}

function getCoinRate(coin, currency) {
  if (!coin) coin = defaultCoin;
  if (!currency) currency = defaultCurrency;
  coinToCurrencyRate = getIguanaRate(coin + "/" + currency);
  // graceful fallback
  // if iguana is not present get a quote form an external source
  if (!coinToCurrencyRate || coinToCurrencyRate === 0)
    return getExternalRate(coin + "/" + currency);
}

// construct coins to add array
function constructCoinRepeater() {
  var result = "";

  for (var i=0; i < availableCoinsToAdd.length; i++) {
    result += coinRepeaterTemplate.replace("{{ id }}", availableCoinsToAdd[i].id.toUpperCase()).
                                   replace("{{ coin_id }}", availableCoinsToAdd[i].id.toLowerCase()).
                                   replace("{{ name }}", availableCoinsToAdd[i].name).
                                   replace("{{ color }}", availableCoinsToAdd[i].color);
  }

  return result;
}

var accountCoinRepeaterTemplate = "<div class=\"item{{ active }}\" data-coin-id=\"{{ coin_id }}\">" +
                                      "<div class=\"coin\">" +
                                        "<i class=\"icon cc {{ id }}-alt\"></i>" +
                                        "<span class=\"name\">{{ name }}</span>" +
                                      "</div>" +
                                      "<div class=\"balance\">" +
                                        "<div class=\"coin-value\"><span class=\"val\">{{ coin_value }}</span> {{ coin_id }}</div>" +
                                        "<div class=\"currency-value\"><span class=\"val\">{{ currency_value }}</span> {{ currency_name }}</div>" +
                                      "</div>" +
                                    "</div>";

// construct account coins array
function constructAccountCoinRepeater() {
  var result = "";
  var accountCoinRepeaterHTML = $(".account-coins-repeater").html();
  var isActiveCoinSet = accountCoinRepeaterHTML.indexOf("item active") > -1 ? true : false;

  if (!$(".account-coins-repeater .item").length) {
    coinsSelectedByUser[0] = defaultCoin.toLowerCase();
  }

  for (var i=0; i < coinsSelectedByUser.length; i++) {
    if (accountCoinRepeaterHTML.indexOf('data-coin-id="' + coinsSelectedByUser[i] + '"') === -1) {
      var coinLocalRate = coinToCurrencyRate;

      // call API
      // note(!): if coin is not added yet it will take a while iguana to enable RT relay
      //addCoin(coinsSelectedByUser[i]);
      var coinBalance = getBalance(defaultAccount);

      if (coinsSelectedByUser[i].toUpperCase() !== defaultCoin) {
        coinLocalRate = getCoinRate(coinsSelectedByUser[i].toUpperCase());
      }
      var coinData = getCoinData(coinsSelectedByUser[i]);
      result += accountCoinRepeaterTemplate.replace("{{ id }}", coinData.id.toUpperCase()).
                                     replace("{{ name }}", coinData.name).
                                     replace("{{ coin_id }}", coinData.id.toLowerCase()).
                                     replace("{{ coin_id }}", coinData.id.toUpperCase()).
                                     replace("{{ currency_name }}", defaultCurrency).
                                     replace("{{ coin_value }}", coinBalance).
                                     replace("{{ currency_value }}", (coinBalance * coinLocalRate).toFixed(2)).
                                     replace("{{ active }}", i === 0 && !isActiveCoinSet ? " active" : "");
    }
  }

  return result;
}

var transactionUnitRepeater = "<div class=\"item {{ status_class }} {{ timestamp_format }}\">" +
                                "<div class=\"status\">{{ status }}</div>" +
                                "<div class=\"amount\">" +
                                  "<span class=\"value\">{{ amount }}</span>" +
                                  "<span class=\"coin-name\">{{ coin }}</span>" +
                                "</div>" +
                                "<div class=\"progress-status\">" +
                                  "<i class=\"icon\"></i>" +
                                "</div>" +
                                "<div class=\"hash\">{{ hash }}</div>" +
                                "<div class=\"timestamp\">{{ timestamp_single }}</div>" +
                                "<div class=\"timestamp two-lines\">" +
                                  "<div class=\"timestamp-date\">{{ timestamp_date }}</div>" +
                                  "<div class=\"timestamp-time\">{{ timestamp_time }}</div>" +
                                "</div>" +
                              "</div>";

// construct transaction unit array
// TODO: add edge case "no transactions" for a selected coin
function constructTransactionUnitRepeater() {
  var result = "";

  var selectedCoin = $(".account-coins-repeater .item.active");
  var coinName = selectedCoin.attr("data-coin-id").toUpperCase();

  var transactionsList = listTransactions(defaultAccount);

  for (var i=0; i < transactionsList.length; i++) {
    if (transactionsList[0].txid) {
      // TODO: add account address check like http://127.0.0.1:7778/api/bitcoinrpc/getaccount?address=RJfVbb1sGagbE2SeEZPiEzCC2Z49H9ufmp
      // call gettransaction to get status, value and datetime of transaction
      var transactionDetails = getTransaction(transactionsList[0].txid);
      result += transactionUnitRepeater.replace("{{ status }}", "N/A").
                                     replace("{{ status_class }}", "received").
                                     replace("{{ amount }}", 2).
                                     replace("{{ timestamp_format }}", "timestamp-multi").
                                     replace("{{ coin }}", coinName).
                                     replace("{{ hash }}", transactionsList[0].txid).
                                     replace("{{ timestamp_date }}", timeConverter(transactionDetails.timestamp, "DDMMMYYYY")).
                                     replace("{{ timestamp_time }}", timeConverter(transactionDetails.timestamp, "HHMM"));
    }
  }
  return result;
}

function updateTotalBalance() {
  var totalBalance = 0;
  $(".account-coins-repeater .item").each(function(index, item) {
    var coin = $(this).attr("data-coin-id");
    var coinValue = $(this).find(".coin-value .val");
    var currencyValue = $(this).find(".currency-value .val");

    totalBalance += Number(coinValue.html()) * getCoinRate(coin.toUpperCase());
  });

  $(".balance-block .balance .value").html(totalBalance.toFixed(2));
  $(".balance-block .balance .currency").html(defaultCurrency);
}

function updateTransactionUnitBalance(isAuto) {
  var selectedCoin = $(".account-coins-repeater .item.active");
  var currentCoinRate = isAuto ? getCoinRate(selectedCoin.attr("data-coin-id").toUpperCase()) : parseFloat($(".account-coins-repeater .item.active .currency-value .val").html())/parseFloat($(".account-coins-repeater .item.active .coin-value .val").html());
  var selectedCoinValue = Number($(".account-coins-repeater .item.active .coin-value .val").html());
  $(".transactions-unit .active-coin-balance .value").html(selectedCoinValue);
  $(".transactions-unit .active-coin-balance .coin-name").html(selectedCoin.attr("data-coin-id").toUpperCase());
  $(".transactions-unit .active-coin-balance-currency .value").html((selectedCoinValue * currentCoinRate).toFixed(2));
  $(".transactions-unit .active-coin-balance-currency .currency").html(defaultCurrency.toUpperCase());
}

function updateAccountCoinRepeater() {
  $(".account-coins-repeater .item").each(function(index, item) {
    var coin = $(this).attr("data-coin-id");
    var coinValue = $(this).find(".coin-value .val");
    var currencyValue = $(this).find(".currency-value .val");

    currencyValue.html((Number(coinValue.html()) * getCoinRate(coin.toUpperCase())).toFixed(2));
  });
}

function updateDashboardView(timeout) {
  var dashboardUpdateTimer = setInterval(function() {
    updateRates();
    updateTotalBalance();
    updateAccountCoinRepeater();
    updateTransactionUnitBalance(true);
    console.log("dashboard rate updated");
  }, timeout * 1000);
}

function getCoinData(coinId) {
  for (var i=0; i < availableCoinsToAdd.length; i++) {
    if (availableCoinsToAdd[i].id.toString() === coinId.toString())
      return availableCoinsToAdd[i];
  }

  return false;
}

function bindClickInAccountCoinRepeater() {
  $(".account-coins-repeater .item").each(function(index, item) {
    $(this).click(function() {
      $(".account-coins-repeater .item").filter(":visible").removeClass("active");
      if ($(this).hasClass("active")) {
        $(this).removeClass("active");
      } else {
        $(this).addClass("active");
        updateTransactionUnitBalance();
        constructTransactionUnitRepeater();
      }
    });
  });
}

function bindClickInCoinRepeater() {
  $(".supported-coins-repeater .coin").each(function(index, item) {
    $(this).click(function() {
      if ($(this).hasClass("active")) {
        delete coinsSelectedByUser[index];
        $(this).removeClass("active");
      } else {
        $(this).addClass("active");
        coinsSelectedByUser[index] = $(this).attr("data-coin-id");
      }
    });
  });
}

function bindCoinRepeaterSearch() {
  $(".quick-search .input").keyup(function() {
    var quickSearchVal = $(this).val().toLowerCase();

    $(".supported-coins-repeater .coin .name").each(function(index, item) {
      var itemText = $(item).text().toString().toLowerCase();

      if (itemText.indexOf(quickSearchVal) > -1)
        $(this).parent().removeClass("fade");
      else
        $(this).parent().addClass("fade");
    });

    // fade in elements if nothing was found
    if ($(".supported-coins-repeater .coin").filter(".fade").length === availableCoinsToAdd.length)
      $(".supported-coins-repeater .coin").filter(".fade").removeClass("fade");
  });
}