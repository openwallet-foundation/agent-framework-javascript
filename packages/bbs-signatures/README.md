<p align="center">
  <br />
  <img
    alt="Credo Logo"
    src="https://github.com/openwallet-foundation/credo-ts/blob/c7886cb8377ceb8ee4efe8d264211e561a75072d/images/credo-logo.png"
    height="250px"
  />
</p>
<h1 align="center"><b>Credo BBS+ Module</b></h1>
<p align="center">
  <a
    href="https://raw.githubusercontent.com/openwallet-foundation/credo-ts/main/LICENSE"
    ><img
      alt="License"
      src="https://img.shields.io/badge/License-Apache%202.0-blue.svg"
  /></a>
  <a href="https://www.typescriptlang.org/"
    ><img
      alt="typescript"
      src="https://img.shields.io/badge/%3C%2F%3E-TypeScript-%230074c1.svg"
  /></a>
    <a href="https://www.npmjs.com/package/@credo-ts/bbs-signatures"
    ><img
      alt="@credo-ts/bbs-signatures version"
      src="https://img.shields.io/npm/v/@credo-ts/bbs-signatures"
  /></a>

</p>
<br />

Credo BBS Module provides an optional addon to Credo to use BBS signatures in W3C VC exchange.

## Installation

```sh
# or npm/yarn
pnpm add @credo-ts/bbs-signatures
```

### React Native

When using Credo inside the React Native environment, temporarily, a dependency for creating keys, signing and verifying, with bbs keys must be swapped. Inside your `package.json` the following must be added. This is only needed for React Native environments

#### yarn

```diff
+   "resolutions": {
+     "@mattrglobal/bbs-signatures": "@animo-id/react-native-bbs-signatures@^0.1.0",
+   },
    "dependencies": {
      ...
+     "@animo-id/react-native-bbs-signatures": "^0.1.0",
    }
```

#### npm

```diff
+   "overrides": {
+     "@mattrglobal/bbs-signatures": "@animo-id/react-native-bbs-signatures@^0.1.0",
+   },
    "dependencies": {
      ...
+     "@animo-id/react-native-bbs-signatures": "^0.1.0",
    }
```

#### pnpm

```diff
+   "pnpm": {
+       overrides": {
+          "@mattrglobal/bbs-signatures": "npm:@animo-id/react-native-bbs-signatures@^0.1.0",
+       }
+   },
    "dependencies": {
      ...
+     "@animo-id/react-native-bbs-signatures": "^0.1.0",
    }
```

The resolution field says that any instance of `@mattrglobal/bbs-signatures` in any child dependency must be swapped with `@animo-id/react-native-bbs-signatures`.

The added dependency is required for autolinking and should be the same as the one used in the resolution.

[React Native Bbs Signature](https://github.com/animo/react-native-bbs-signatures) has some quirks with setting it up correctly. If any errors occur while using this library, please refer to their README for the installation guide.

### Issue with `node-bbs-signatures`

Right now some platforms will see an "error" when installing the `@credo-ts/bbs-signatures` package. This is because the BBS signatures library that we use under the hood is built for Linux x86 and MacOS x86 (and not Windows and MacOS arm). This means that it will show that it could not download the binary. This is not an error for developers, the library that fails is `node-bbs-signatures` and is an optional dependency for performance improvements. It will fallback to a (slower) wasm build.
