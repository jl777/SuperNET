/*!
 * Iguana localstorage
 * info: simple local storage manager
 */

 // TODO: add browser localstorage api compatibility check

var localStorageProto = function() {};

localStorageProto.prototype.getVal = function(name) {
  return JSON.parse(localStorage.getItem(name));
}

localStorageProto.prototype.deleteVal = function(name) {
  return localStorage.removeItem(name);
}

localStorageProto.prototype.setVal = function(name, propArray) {
  localStorage.setItem(name, JSON.stringify(propArray));
}