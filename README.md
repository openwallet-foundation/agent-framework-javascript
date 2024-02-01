<p align="center">
  <br />
  <img
    alt="Credo Logo"
    src="https://github.com/openwallet-foundation/credo-ts/blob/c7886cb8377ceb8ee4efe8d264211e561a75072d/images/credo-logo.png"
    height="250px"
  />
</p>
<h1 align="center"><b>Credo</b></h1>
<p align="center">
  <img
    alt="Pipeline Status"
    src="https://github.com/openwallet-foundation/credo-ts/workflows/Continuous%20Integration/badge.svg?branch=main"
  />
  <a href="https://codecov.io/gh/openwallet-foundation/credo-ts/"
    ><img
      alt="Codecov Coverage"
      src="https://img.shields.io/codecov/c/github/openwallet-foundation/credo-ts/coverage.svg?style=flat-square"
  /></a>
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
</p>
<br />

<p align="center">
  <a href="#features">Features</a> &nbsp;|&nbsp;
  <a href="#getting-started">Getting started</a> &nbsp;|&nbsp;
  <a href="#contributing">Contributing</a> &nbsp;|&nbsp;
  <a href="#license">License</a> 
</p>

Credo is a framework written in TypeScript for building **SSI Agents and DIDComm services** that aims to be **compliant and interoperable** with the standards defined in the [Aries RFCs](https://github.com/hyperledger/aries-rfcs).

> **Note**
> The Aries Framework JavaScript project has recently been rebranded to "Credo" and was moved from the Hyperledger Foundation to the Open Wallet Foundation.
> We are currently in the process of changing the name of the project to Credo, and updating all the documentation and links to reflect this change.
> You may encounter some broken links, or references to the old name, but we are working hard to fix this. Once the new name has been decided
> we will update this README and all the documentation to reflect this change.
> You can follow this discussion for updates about the name: https://github.com/openwallet-foundation/agent-framework-javascript/discussions/1668

## Features

See [Supported Features](https://credo.js.org/guides/features) on the Credo website for a full list of supported features.

- 🏃 Runs in React Native & Node.JS
- 🔒 DIDComm v1 support
- 🌎 [Aries Interop Profile](https://github.com/hyperledger/aries-rfcs/blob/main/concepts/0302-aries-interop-profile/README.md) v1 & v2 support
  - With support for Chat, Mediator Coordination, Indy Credentials & and JSON-LD Credentials sub-targets
- `did:web`, `did:key`, `did:jwk`, `did:peer`, `did:sov`, `did:indy` and `did:cheqd`, with pluggable interface for registering custom did methods.
- OpenID for Verifiable Credentials
- W3C Verifiable Credentials, SD-JWT VCs and AnonCreds
- 💡 Smart Auto Acceptance of Connections, Credentials and Proofs
- 🏢 Multi tenant module for managing multiple tenants under a single agent.

### Packages

<table>
  <tr>
    <th><b>Package</b></th>
    <th><b>Version</b></th>
  </tr>
  <tr>
    <td>@credo-ts/core</td>
    <td>
      <a href="https://npmjs.com/package/@credo-ts/core">
        <img alt="@credo-ts/core version" src="https://img.shields.io/npm/v/@credo-ts/core"/>
      </a>
    </td>
  </tr>
  <tr>
    <td>@credo-ts/node</td>
    <td>
      <a href="https://npmjs.com/package/@credo-ts/node">
        <img alt="@credo-ts/node version" src="https://img.shields.io/npm/v/@credo-ts/node"/>
      </a>
    </td>
  </tr>
  <tr>
    <td>@credo-ts/react-native</td>
    <td>
      <a href="https://npmjs.com/package/@credo-ts/react-native">
        <img alt="@credo-ts/react-native version" src="https://img.shields.io/npm/v/@credo-ts/react-native"/>
      </a>
    </td>
  </tr>
  <tr>
    <td>@aries-framework/indy-vdr</td>
    <td>
      <a href="https://npmjs.com/package/@credo-ts/indy-vdr">
        <img alt="@credo-ts/indy-vdr version" src="https://img.shields.io/npm/v/@credo-ts/indy-vdr"/>
      </a>
    </td>
  </tr>
  <tr>
    <td>@credo-ts/cheqd</td>
    <td>
      <a href="https://npmjs.com/package/@credo-ts/cheqd">
        <img alt="@credo-ts/cheqd version" src="https://img.shields.io/npm/v/@credo-ts/cheqd"/>
      </a>
    </td>
  </tr>  
  <tr>
    <td>@credo-ts/askar</td>
    <td>
      <a href="https://npmjs.com/package/@credo-ts/askar">
        <img alt="@credo-ts/askar version" src="https://img.shields.io/npm/v/@credo-ts/askar"/>
      </a>
    </td>
  </tr>
  <tr>
    <td>@credo-ts/anoncreds</td>
    <td>
      <a href="https://npmjs.com/package/@credo-ts/anoncreds">
        <img alt="@credo-ts/anoncreds version" src="https://img.shields.io/npm/v/@credo-ts/anoncreds"/>
      </a>
    </td>
  </tr>
  <tr>
    <td>@credo-ts/openid4vc-client</td>
    <td>
      <a href="https://npmjs.com/package/@credo-ts/openid4vc-client">
        <img alt="@credo-ts/openid4vc-client version" src="https://img.shields.io/npm/v/@credo-ts/openid4vc-client"/>
      </a>
    </td>
  </tr>
   <tr>
    <td>@credo-ts/action-menu</td>
    <td>
      <a href="https://npmjs.com/package/@credo-ts/action-menu">
        <img alt="@credo-ts/action-menu version" src="https://img.shields.io/npm/v/@credo-ts/action-menu"/>
      </a>
    </td>
  </tr>
    <td>@credo-ts/question-answer</td>
    <td>
      <a href="https://npmjs.com/package/@credo-ts/question-answer">
        <img alt="@credo-ts/question-answer version" src="https://img.shields.io/npm/v/@credo-ts/question-answer"/>
      </a>
    </td>
  </tr>
  <tr>
    <td>@credo-ts/tenants</td>
    <td>
      <a href="https://npmjs.com/package/@credo-ts/tenants">
        <img alt="@credo-ts/tenants version" src="https://img.shields.io/npm/v/@credo-ts/tenants"/>
      </a>
    </td>
  </tr>
  <tr>
    <td><s>@aries-framework/indy-sdk</s> (deprecated, unmaintained after 0.4.x)</td>
    <td>
      <a href="https://npmjs.com/package/@aries-framework/indy-sdk">
        <img alt="@aries-framework/indy-sdk version" src="https://img.shields.io/npm/v/@aries-framework/indy-sdk"/>
      </a>
    </td>
  </tr>
  <tr>
    <td><s>@aries-framework/anoncreds-rs</s> (deprecated and combined with <code>@credo-ts/anoncreds</code>)</td>
    <td>
      <a href="https://npmjs.com/package/@aries-framework/anoncreds-rs">
        <img alt="@aries-framework/anoncreds-rs version" src="https://img.shields.io/npm/v/@aries-framework/anoncreds-rs"/>
      </a>
    </td>
  </tr>
</table>

## Getting Started

Documentation on how to get started with Credo can be found at https://credo.js.org/

### Demo

To get to know the Credo flow, we built a demo to walk through it yourself together with agents Alice and Faber.

You can run the demo in the [`/demo`](/demo) directory of this repository.

## Contributing

If you would like to contribute to the framework, please read the [Framework Developers README](/DEVREADME.md) and the [CONTRIBUTING](/CONTRIBUTING.md) guidelines. These documents will provide more information to get you started!

There are regular community working groups to discuss ongoing efforts within the framework, showcase items you've built with Credo, or ask questions. See [Meeting Information](https://github.com/openwallet-foundation/credo-ts/wiki/Meeting-Information) for up to date information on the meeting schedule. Everyone is welcome to join!

We welcome you to join our mailing list and Discord channel. See the [Wiki](https://github.com/openwallet-foundation/credo-ts/wiki/Communication) for up to date information.

## License

OpenWallet Foundation Credo is licensed under the [Apache License Version 2.0 (Apache-2.0)](/LICENSE).
