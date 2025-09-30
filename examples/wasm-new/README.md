# Tari WASM Scanner Example

This directory contains examples demonstrating how to use the Tari WASM Scanner in web browser.

## Files

- **`scanner-new.html`** - Example showing scanning in a browser using WASM

## Quick Start

### 1. Prerequisites

Install the required tools:

```bash
# Install wasm-pack
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# Install the wasm32 target
rustup target add wasm32-unknown-unknown
```

### 2. Build the WASM Package

```bash
cd ../..
wasm-pack build --target web --out-dir ./examples/wasm-new/pkg-web/
```

### 3. Run http server locally to serve `scanner-new.html`

```bash
cd ./examples/wasm-new
python3 -m http.server 8000
```


### 4. Open the example

Open `http://localhost:8000/scanner-new.html` in browser.
