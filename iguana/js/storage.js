var Storage = (function() {

  return {
    save: function(key, value) {
      return new Promise(function(resolve, reject) {
        var objToSave = {};
        objToSave[key] = value;
        chrome.storage.local.set(objToSave, resolve);
        });
    },
    load: function(key) {
      return new Promise(function(resolve, reject) {
        chrome.storage.local.get(key, function(data) {
          resolve(data[key]);
        });
      });
    },
    remove: function(key) {
      return new Promise(function(resolve, reject) {
        chrome.storage.local.remove(key, resolve);
      });
    }
  };
})();