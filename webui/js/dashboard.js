/*!
 * Iguana dashboard
 *
 */

var defaultCurrency = "USD",
    defaultCoin = "BTCD"; // temp deprecated
    defaultCoinValue = 0,
    defaultCurrencyValue = 0,
    coinToCurrencyRate = 0,
    defaultAccount = "*", // note: change to a specific account name if needed
    coinsSelectedByUser = [],
    decimalPlacesCoin = 1, // note: change decimalPlacesCoin and decimalPlacesCurrency to higher values
    decimalPlacesCurrency = 2, //   in case you have too small coin balance value e.g. 0.0001 BTC
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
  var session = new helperProto();

  // current implementation works only with one coin at a time
  // coin is auto detected based on available portp2p
  if (activeCoin) defaultCoin = activeCoin.toUpperCase();

  if (session.checkSession(true)) {
    $(".dashboard").removeClass("hidden");
    updateRates();
    $(".account-coins-repeater").html(constructAccountCoinRepeater());
    $(".transactions-list-repeater").html(constructTransactionUnitRepeater());
    updateTotalBalance();
    updateTransactionUnitBalance();
    updateDashboardView(dashboardUpdateTimout);
  } else {
    helperProto.prototype.openPage("login");
  }

  $(".top-menu .item").click(function() {
    $(".top-menu .item").each(function(index, item) {
      $(this).removeClass("active");
    });

    $(this).addClass("active");
    // $(this).attr("data-url")
    // TODO: add routing
  });

  $(".lnk-logout").click(function() {
    session.logout();
  });

  $(".btn-add-coin,.btn-close").click(function() {
    var helper = new helperProto();

    helper.toggleModalWindow("add-new-coin-form", 300);
    coinsSelectedByUser = [];
    $(".supported-coins-repeater").html(constructCoinRepeater());
    bindClickInCoinRepeater();
  });
  $(".btn-next").click(function() {
    var helper = new helperProto();

    helper.toggleModalWindow("add-new-coin-form", 300);
    coinsSelectedByUser = helper.reindexAssocArray(coinsSelectedByUser);
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
  var api = new apiProto();

  if (!coin) coin = defaultCoin;
  if (!currency) currency = defaultCurrency;
  coinToCurrencyRate = api.getIguanaRate(coin + "/" + currency);
  // graceful fallback
  // if iguana is not present get a quote form external source
  if (!coinToCurrencyRate || coinToCurrencyRate === 0) coinToCurrencyRate = api.getExternalRate(coin + "/" + currency);
}

function getCoinRate(coin, currency) {
  var api = new apiProto();

  if (!coin) coin = defaultCoin;
  if (!currency) currency = defaultCurrency;
  coinToCurrencyRate = api.getIguanaRate(coin + "/" + currency);
  // graceful fallback
  // if iguana is not present get a quote form an external source
  if (!coinToCurrencyRate || coinToCurrencyRate === 0)
    return api.getExternalRate(coin + "/" + currency);
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
      // addCoin(coinsSelectedByUser[i]);
      var api = new apiProto();
      var coinBalance = api.getBalance(defaultAccount);
      console.log(coinBalance);

      if (coinsSelectedByUser[i].toUpperCase() !== defaultCoin) {
        coinLocalRate = getCoinRate(coinsSelectedByUser[i].toUpperCase());
      }
      var coinData = getCoinData(coinsSelectedByUser[i]);

      if (i === 0 && !isActiveCoinSet) activeCoin = coinData.id;
      result += accountCoinRepeaterTemplate.replace("{{ id }}", coinData.id.toUpperCase()).
                                            replace("{{ name }}", coinData.name).
                                            replace("{{ coin_id }}", coinData.id.toLowerCase()).
                                            replace("{{ coin_id }}", coinData.id.toUpperCase()).
                                            replace("{{ currency_name }}", defaultCurrency).
                                            replace("{{ coin_value }}", coinBalance ? coinBalance.toFixed(decimalPlacesCurrency) : 0).
                                            replace("{{ currency_value }}", (coinBalance * coinLocalRate).toFixed(decimalPlacesCurrency)).
                                            replace("{{ active }}", i === 0 && !isActiveCoinSet ? " active" : "");
    }
  }

  return result;
}

var transactionUnitRepeater = "<div class=\"item {{ status_class }} {{ timestamp_format }}\">" +
                                "<div class=\"status\">{{ status }}</div>" +
                                "<div class=\"amount\">" +
                                  "<span class=\"in-out {{ in_out }}\"></span>" +
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
  var helper = new helperProto();
  var api = new apiProto();

  var selectedCoin = $(".account-coins-repeater .item.active");
  var coinName = selectedCoin.attr("data-coin-id").toUpperCase();

  var transactionsList = api.listTransactions(defaultAccount);
  // sort tx in desc order by timestamp
  // iguana transactionslist method is missing timestamp field in response, straight forward sorting cannot be done
  if (transactionsList[0])
    if (transactionsList[0].time) transactionsList.sort(function(a, b) { return b.time - a.time });

  for (var i=0; i < transactionsList.length; i++) {
    if (transactionsList[i].txid) {
      // TODO: add func to evaluate tx time in seconds/minutes/hours/a day from now e.g. "a moment ago", "1 day ago" etc
      // timestamp is converted to 24h format
      var transactionDetails = api.getTransaction(transactionsList[i].txid),
          txIncomeOrExpenseFlag = "",
          txStatus = "N/A",
          txCategory = "",
          txAddress = "",
          txAmount = "N/A";

      if (transactionDetails)
        if (transactionDetails.details) {
          txAddress = transactionDetails.details[0].address;
          txAmount = Math.abs(transactionDetails.details[0].amount);
          // non-iguana
          if (transactionDetails.details[0].category)
            txCategory = transactionDetails.details[0].category;

            if (transactionDetails.details[0].category === "send") {
              txIncomeOrExpenseFlag = "bi_interface-minus";
              txStatus = "sent";
            } else {
              txIncomeOrExpenseFlag = "bi_interface-plus";
              txStatus = "received";
            }
        } else {
          // iguana
          txAddress = transactionsList[i].address;
          txAmount = transactionDetails.vout[1].value;
        }

      if (transactionDetails)
        result += transactionUnitRepeater.replace("{{ status }}", txStatus).
                                          replace("{{ status_class }}", txCategory).
                                          replace("{{ in_out }}", txIncomeOrExpenseFlag).
                                          replace("{{ amount }}", txAmount).
                                          replace("{{ timestamp_format }}", "timestamp-multi").
                                          replace("{{ coin }}", coinName).
                                          replace("{{ hash }}", txAddress).
                                          replace("{{ timestamp_date }}", helper.convertUnixTime(transactionDetails.timestamp || transactionDetails.time, "DDMMMYYYY")).
                                          replace("{{ timestamp_time }}", helper.convertUnixTime(transactionDetails.timestamp || transactionDetails.time, "HHMM"));
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

  $(".balance-block .balance .value").html(totalBalance.toFixed(decimalPlacesCurrency));
  $(".balance-block .balance .currency").html(defaultCurrency);
}

function updateTransactionUnitBalance(isAuto) {
  var selectedCoin = $(".account-coins-repeater .item.active");
  var currentCoinRate = isAuto ? getCoinRate(selectedCoin.attr("data-coin-id").toUpperCase()) : parseFloat($(".account-coins-repeater .item.active .currency-value .val").html()) / parseFloat($(".account-coins-repeater .item.active .coin-value .val").html());
  var selectedCoinValue = Number($(".account-coins-repeater .item.active .coin-value .val").html()) ? Number($(".account-coins-repeater .item.active .coin-value .val").html()) : 0;

  $(".transactions-unit .active-coin-balance .value").html(selectedCoinValue.toFixed(decimalPlacesCoin));
  $(".transactions-unit .active-coin-balance .coin-name").html(selectedCoin.attr("data-coin-id").toUpperCase());
  $(".transactions-unit .active-coin-balance-currency .value").html((selectedCoinValue * currentCoinRate).toFixed(decimalPlacesCurrency));
  $(".transactions-unit .active-coin-balance-currency .currency").html(defaultCurrency.toUpperCase());
}

function updateAccountCoinRepeater() {
  $(".account-coins-repeater .item").each(function(index, item) {
    var coin = $(this).attr("data-coin-id");
    var coinValue = $(this).find(".coin-value .val");
    var currencyValue = $(this).find(".currency-value .val");
    var currenyValueCalculated = (Number(coinValue.html()) * getCoinRate(coin.toUpperCase())).toFixed(decimalPlacesCoin);

    currencyValue.html(Number(currenyValueCalculated) ? currenyValueCalculated : 0);
  });
}

function updateDashboardView(timeout) {
  var helper = new helperProto();
  var dashboardUpdateTimer = setInterval(function() {
    console.clear();
    helper.checkSession();
    updateRates();
    updateTotalBalance();
    updateAccountCoinRepeater();
    updateTransactionUnitBalance(true);
    $(".transactions-list-repeater").html(constructTransactionUnitRepeater());
    console.log("dashboard updated");
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
        /* don't remove
        console.log($(this).attr("data-coin-id"));
        activeCoin = $(this).attr("data-coin-id");
        */
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