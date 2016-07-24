/*!
 * Iguana login
 *
 */

$(document).ready(function() {
  $(".btn-signin").click(function() {
    // validate passphrase
    // condition: 24 words in lower case followed by a single space character
    var passphraseInput = $("#passphrase").val();
    var totalSubstr = passphraseInput.match(/\b\w+\b/g);
    var totalSubstrAlpha = passphraseInput.match(/\b[a-z]+\b/g); // count only words consisted of characters
    var totalSpaces = passphraseInput.match(/\s/g);

    if (totalSubstr.length === 24 && totalSubstrAlpha.length === 24 && totalSpaces.length === 23) {
      if (walletLogin(passphraseInput)) {
        toggleLoginErrorStyling(false);
        document.location = "dashboard.html";
      } else {
        toggleLoginErrorStyling(true);
      }
    } else {
      toggleLoginErrorStyling(true);
    }
  });
  $("#passphrase").keyup(function() {
    if ($("#passphrase").val().length > 0) {
      $(".btn-signin").removeClass("disabled");
    } else {
      $(".btn-signin").addClass("disabled");
    }
  });
});

function toggleLoginErrorStyling(isError) {
  if (isError) {
    $("#passphrase").addClass("error");
    $(".login-input-directions-error.col-red").removeClass("hidden");
    $(".login-input-directions").addClass("hidden");
  } else {
    $("#passphrase").removeClass("error");
    $(".login-input-directions-error.col-red").addClass("hidden");
  }
}