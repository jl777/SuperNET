/*!
 * Iguana localstorage
 * info: simple local storage manager
 */

function localstorageGetVal(name) {
  return localStorage.getItem(name);
}

function localstorageDeleteVal(name) {
  return localStorage.removeItem(name);
}

function localstorageSetVal(name, propArray) {           // TODO(?): encrypt
  localStorage.setItem(name, JSON.stringify(propArray)); // potential security flaw
}