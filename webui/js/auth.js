/*!
 * Iguana authorization
 *
 */

$(document).ready(function() {
  // this should do as simple check whether it's a login or account create page
  if ($(".login-form").width()) {
    var savedPassphrase = JSON.parse(localstorageGetVal("iguanaPassphrase"));

    addAuthorizationButtonAction("signin");
    watchPassphraseKeyUpEvent("signin");

    if (savedPassphrase.passphrase && savedPassphrase.isConfirmed === "yes")
      $("#passphrase").val(savedPassphrase.passphrase);
      $(".btn-signin").removeClass("disabled");

    $(".login-form .btn-signup").click(function() {
      openPage("create-account");
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

    if (totalSubstr && totalSubstrAlpha && totalSpaces)
      if (totalSubstr.length === 24 && totalSubstrAlpha.length === 24 && totalSpaces.length === 23) {
        if (buttonClassName === "signin" ? walletLogin(passphraseInput) : walletCreate(passphraseInput) && verifyNewPassphrase()) {
          toggleLoginErrorStyling(false);
          openPage("dashboard");
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
  var savedPassphrase = JSON.parse(localstorageGetVal("iguanaPassphrase"));

  if (savedPassphrase.passphrase === $("#passphrase").val() && savedPassphrase.isConfirmed === "no") {
    savedPassphrase.isConfirmed = "yes";
    localstorageSetVal("iguanaPassphrase", savedPassphrase);
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
    openPage("login");
  });

  $(".btn-verify-passphrase").click(function() {
    // isConfirmed is required to check if a user can verify a passphrase on the 2nd step
    localstorageSetVal("iguanaPassphrase", { "passphrase" : $(".generated-passhprase").text(), "isConfirmed": "no" });
    $(".create-account-form").addClass("hidden");
    $(".verify-passphrase-form").removeClass("hidden");
  });
}