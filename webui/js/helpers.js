/*!
 * Iguana helpers
 * info: various reusable functions go here
 */

var helperProto = function() {};

var defaultSessionLifetime = 3600; // sec

helperProto.prototype.convertUnixTime = function(UNIX_timestamp, format) {
  var a = new Date(UNIX_timestamp * 1000);
  var months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  var year = a.getFullYear();
  var month = months[a.getMonth()];
  var date = a.getDate();
  var hour = a.getHours() < 10 ? '0' + a.getHours() : a.getHours();
  var min = a.getMinutes() < 10 ? '0' + a.getMinutes() : a.getMinutes();
  var sec = a.getSeconds();

  if (format === 'DDMMMYYYY')
    return date + ' ' + month + ' ' + year + ' ';
  if (format === 'HHMM')
    return hour + ':' + min;
}

helperProto.prototype.reindexAssocArray = function(array) {
  var _array = [], index = 0;

  $.each(array, function(key, value) {
    if (value) {
      _array[index] = value;
      index++;
    }
  });

  return _array;
}

helperProto.prototype.toggleModalWindow = function(formClassName, timeout) {
  var modalWindow = $("." + formClassName);

  if (modalWindow.hasClass("fade")) {
    modalWindow.removeClass("hidden");
    setTimeout(function() {
      modalWindow.removeClass("fade");
    }, 10);
  } else {
    modalWindow.addClass("fade");
    setTimeout(function() {
      modalWindow.addClass("hidden");
    }, timeout);
  }
}

// simple page router
helperProto.prototype.openPage = function(url) {
  var localPageUrl;

  switch (url) {
    case "login":
      localPageUrl = "login.html";
      break;
    case "create-account":
      localPageUrl = "create-account.html";
      break;
    case "dashboard":
      localPageUrl = "dashboard.html";
      break;
    case "settings":
      localPageUrl = "reference-currency.html";
      break;
  }

  document.location = localPageUrl;
}

helperProto.prototype.checkSession = function(returnVal) {
  var localStorage = new localStorageProto();
  if (!localStorage.getVal("iguana-auth")) helperProto.prototype.logout();
  var currentEpochTime = new Date(Date.now()) / 1000; // calc difference in seconds between current time and session timestamp
  var secondsElapsedSinceLastAuth = Number(currentEpochTime) - Number(localStorage.getVal("iguana-auth").timestamp / 1000);

  if (secondsElapsedSinceLastAuth > defaultSessionLifetime) {
    if (!returnVal) {
      if (!$(".login-form").width()) helperProto.prototype.openPage("login"); // redirect to login when session is expired
    } else {
      return false;
    }
  } else {
    return true;
  }
}

// TODO: add walletlock
helperProto.prototype.logout = function() {
  var localStorage = new localStorageProto();
  localStorage.setVal("iguana-auth", { "timestamp" : 1471620867 }); // Jan 01 1970
  helperProto.prototype.openPage("login");
}

helperProto.prototype.setCurrency = function(currencyShortName) {
  var localStorage = new localStorageProto();
  localStorage.setVal("iguana-currency", { "name" : currencyShortName });
}

helperProto.prototype.getCurrency = function() {
  var localStorage = new localStorageProto();
  return localStorage.getVal("iguana-currency");
}