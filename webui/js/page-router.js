/*!
 * Iguana page router
 * info: simple page router
 */

 function openPage(url) {
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
    }

    document.location = localPageUrl;
 }