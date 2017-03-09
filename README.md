-----

:warning: *THIS PROJECT IS NOT OFFICIALLY SUPPORTED! ALL CODE IN HERE IS
IN DEVELOPMENT AND LIKELY TO CHANGE WITHOUT WARNING. USE AT YOUR OWN
RISK.* :warning:

-----

# Wire

This repository is part of the source code of Wire. You can find more information at [wire.com](https://wire.com) or by contacting opensource@wire.com.

You can find the published source code at [github.com/wireapp](https://github.com/wireapp).

For licensing information, see the attached LICENSE file and the list of third-party licenses at [wire.com/legal/licenses/](https://wire.com/legal/licenses/).


## Usage

```javascript
const libsodium = require('libsodium-neon');
const keyPair = libsodium.crypto_sign_keypair();
// keyPair = {publicKey: Uint8Array [118, 200, 242, 168, 123, 173, 221, 232, ...]}
```


## Building

### Requirements

- [Node.js](https://nodejs.org/)
- Rust (use [rustup](https://rustup.rs/))
- [Neon](https://github.com/neon-bindings/neon)


### Installation

Just install the needed packages for this project by running:

```bash
npm install
```

Afterwards the project will be built. For re-building run:

```bash
npm run build
```

To test it with node, run:

```bash
npm test
```


## Speed comparison

System specs: `macOS 10.12 @ 2.6 GHz Intel Core i7, 16 GB RAM`

|**Function**                            |    **ops/sec** |      **ops/sec** | **times faster** |
|:---------------------------------------|---------------:|-----------------:|-----------------:|
|                                        | `libsodium.js` | `libsodium-neon` |                  |
| `crypto_auth_hmacsha256`               |         51,156 |      **55,562**  |             1.09 |
| `crypto_scalarmult`                    |             86 |       **6,129**  |            70.80 |
| `crypto_sign_detached`                 |            251 |       **6,277**  |            25.01 |
| `crypto_sign_ed25519_pk_to_curve25519` |            596 |      **21,030**  |            35.29 |
| `crypto_sign_ed25519_sk_to_curve25519` |         13,390 |      **90,650**  |             6.77 |
| `crypto_sign_keypair`                  |            276 |       **6,602**  |            23.92 |
|                                        |                |                  |                  |
| **Average**                            |         10,959 |      **31,042**  |             2.83 |
