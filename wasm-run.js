const fs = require ('fs');

async function runWasm() {
  const wasmPath = process.env.WASM_PATH;
  if (!wasmPath) throw new Error ('No WASM_PATH');
  const wasmBytes = fs.readFileSync (wasmPath);
  const wasmArray = new Uint8Array (wasmBytes);
  const wasmEnv = {
    bitcoin_ctx_destroy: function() {console.log ('bitcoin_ctx_destroy')}
  };
  const wasmInstantiated = await WebAssembly.instantiate (wasmBytes, {env: wasmEnv});
  const peers_check = wasmInstantiated.instance.exports.peers_check();
  console.log ('peers_check: ' + peers_check);
}

runWasm().catch (ex => console.log (ex));
