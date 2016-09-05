/*!
 * Iguana authorization
 *
 */

var passphraseToVerify;

$(document).ready(function() {
  var localStorage = new localStorageProto();
  var helper = new helperProto();

  // ugly login form check
  if ($(".login-form")) {
    if (helper.checkSession(true)) {
      helper.openPage("dashboard");
    } else {
      $(".login-form").removeClass("hidden");
    }

    addAuthorizationButtonAction("signin");
    watchPassphraseKeyUpEvent("signin");

    $(".login-form .btn-signup").click(function() {
      helper.openPage("create-account");
    });
  }

  if ($(".create-account-form").width()) {
    addAuthorizationButtonAction("add-account");
    watchPassphraseKeyUpEvent("add-account");
    initCreateAccountForm();
  }
});

function addAuthorizationButtonAction(buttonClassName) {
  $(".btn-" + buttonClassName).click(function() {
    // validate passphrase
    // condition: 24 words in lower case followed by a single space character
    var passphraseInput = $("#passphrase").val();
    var totalSubstr = passphraseInput.match(/\b\w+\b/g);
    var totalSubstrAlpha = passphraseInput.match(/\b[a-z]+\b/g); // count only words consist of characters
    var totalSpaces = passphraseInput.match(/\s/g);
    var api = new apiProto();
    var helper = new helperProto();
    var localStorage = new localStorageProto();

    if (totalSubstr && totalSubstrAlpha && totalSpaces)
      // wallet passphrase check is temp disabled to work in coind env
      if (true /*totalSubstr.length === 24 && totalSubstrAlpha.length === 24 && totalSpaces.length === 23*/) {
        if (buttonClassName === "signin" ? api.walletLogin(passphraseInput, defaultSessionLifetime) : api.walletCreate(passphraseInput) && verifyNewPassphrase()) {
          toggleLoginErrorStyling(false);

          if (buttonClassName === "add-account") {
            helper.openPage("login");
          } else {
            localStorage.setVal("iguana-auth", { "timestamp": Date.now() });
            helper.openPage("dashboard");
          }
        } else {
          toggleLoginErrorStyling(true);
        }
      } else {
        toggleLoginErrorStyling(true);
      }
    else
      toggleLoginErrorStyling(true);
  });
}

function watchPassphraseKeyUpEvent(buttonClassName) {
  $("#passphrase").keyup(function() {
    if ($("#passphrase").val().length > 0) {
      $(".btn-" + buttonClassName).removeClass("disabled");
    } else {
      $(".btn-" + buttonClassName).addClass("disabled");
    }
  });
}

function toggleLoginErrorStyling(isError) {
  if (isError) {
    $("#passphrase").addClass("error");
    $(".login-input-directions-error.col-red").removeClass("hidden");
    $(".login-input-directions").addClass("hidden");
  } else {
    $("#passphrase").removeClass("error");
    $(".login-input-directions-error.col-red").addClass("hidden");
  }
  $("#passphrase").val("");
}

function verifyNewPassphrase() {
  var localStorage = new localStorageProto();

  if (passphraseToVerify === $("#passphrase").val()) {
    return true;
  } else {
    return false;
  }
}

function initCreateAccountForm() {
  var newPassphrase = PassPhraseGenerator.generatePassPhrase();

  $(".create-account-form").removeClass("hidden");
  $(".verify-passphrase-form").addClass("hidden");
  $("#passphrase").val("");

  $("#passphrase-saved-checkbox").prop("checked", false);
  $(".generated-passhprase").html(newPassphrase);
  $(".btn-verify-passphrase").addClass("disabled");

  $("#passphrase-saved-checkbox").click(function() {
    if ($("#passphrase-saved-checkbox").prop("checked"))
      $(".btn-verify-passphrase").removeClass("disabled");
    else
      $(".btn-verify-passphrase").addClass("disabled");
  });

  $(".verify-passphrase-form .btn-back").click(function() {
    initCreateAccountForm();
  });

  $(".create-account-form .btn-back").click(function() {
    var helper = new helperProto();
    helper.openPage("login");
  });

  $(".btn-verify-passphrase").click(function() {
    passphraseToVerify = $(".generated-passhprase").text();
    $(".create-account-form").addClass("hidden");
    $(".verify-passphrase-form").removeClass("hidden");
  });
}