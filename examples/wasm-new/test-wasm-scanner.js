const path = require("path");

const wasmPath = path.join(__dirname, "pkg/lightweight_wallet_libs.js");
const wasm = require(wasmPath);

async function run() {
  const version = wasm.get_version();

  console.log(`Version: ${version}`);

  const scanner = await wasm.create_wasm_scanner("park anchor dizzy flat vendor mention hammer decide rug police forum stone erase resource chronic leisure poet machine tomorrow shock garden good glory weekend");

  console.log(`Scanner: ${scanner}`);
  
  wasm.initialize_http_scanner(scanner, "http://192.168.1.100:9000");
}

run()
  .then(() => console.log("Success!"))
  .catch((e) => console.log(`Failed: ${e}`));
