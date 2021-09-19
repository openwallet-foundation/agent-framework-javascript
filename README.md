<p align="center">
  <br />
  <img
    alt="Hyperledger Aries logo"
    src="https://raw.githubusercontent.com/hyperledger/aries-framework-javascript/aa31131825e3331dc93694bc58414d955dcb1129/images/aries-logo.png"
    height="250px"
  />
</p>
<h1 align="center"><b>Aries Framework JavaScript</b></h1>
<p align="center">
  <img
    alt="Pipeline Status"
    src="https://github.com/hyperledger/aries-framework-javascript/workflows/Continuous%20Integration/badge.svg?branch=main"
  />
  <a
    href="https://lgtm.com/projects/g/hyperledger/aries-framework-javascript/context:javascript"
    ><img
      alt="Language grade: JavaScript"
      src="https://img.shields.io/lgtm/grade/javascript/g/hyperledger/aries-framework-javascript.svg?logo=lgtm&logoWidth=18"
  /></a>
  <a href="https://codecov.io/gh/hyperledger/aries-framework-javascript/"
    ><img
      alt="Codecov Coverage"
      src="https://img.shields.io/codecov/c/github/hyperledger/aries-framework-javascript/coverage.svg?style=flat-square"
  /></a>
  <a
    href="https://raw.githubusercontent.com/hyperledger/aries-framework-javascript/main/LICENSE"
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

Aries Framework JavaScript is a framework written in TypeScript for building **SSI Agents and DIDComm services** that aims to be **compliant and interoperable** with the standards defined in the [Aries RFCs](https://github.com/hyperledger/aries-rfcs).

## Features

Some features are not yet supported, but are on our roadmap. Check [the roadmap](https://github.com/hyperledger/aries-framework-javascript/issues/39) for more information.

- ✅ React Native
- ✅ Node.JS
- ✅ Issue Credential Protocol ([RFC 0036](https://github.com/hyperledger/aries-rfcs/blob/master/features/0036-issue-credential/README.md))
- ✅ Present Proof Protocol ([RFC 0037](https://github.com/hyperledger/aries-rfcs/tree/master/features/0037-present-proof/README.md))
- ✅ Connection Protocol ([RFC 0160](https://github.com/hyperledger/aries-rfcs/blob/master/features/0160-connection-protocol/README.md))
- ✅ Basic Message Protocol ([RFC 0095](https://github.com/hyperledger/aries-rfcs/blob/master/features/0095-basic-message/README.md))
- ✅ Mediator Coordination Protocol ([RFC 0211](https://github.com/hyperledger/aries-rfcs/blob/master/features/0211-route-coordination/README.md))
- ✅ Indy Credentials (with `did:sov` support)
- ✅ HTTP Transport
- ✅ Connection-less Issuance and Verification
- ✅ Smart Auto Acceptance of Connections, Credentials and Proofs
- 🚧 Revocation of Indy Credentials
- 🚧 Electron
- 🚧 WebSocket Transport
- ❌ Browser
- ❌ Issue Credential V2, Present Proof V2, DID Exchange Protocol, Out-Of-Band
- ❌ W3C Linked Data VCs, BBS+ Signatures

### Packages

<table>
  <tr>
    <th><b>Package</b></th>
    <th><b>Version</b></th>
  </tr>
  <tr>
    <td>@aries-framework/core</td>
    <td>
      <a href="https://npmjs.com/package/@aries-framework/core">
        <img alt="@aries-framework/core version" src="https://img.shields.io/npm/v/@aries-framework/core"/>
      </a>
    </td>
  </tr>
  <tr>
    <td>@aries-framework/node</td>
    <td>
      <a href="https://npmjs.com/package/@aries-framework/node">
        <img alt="@aries-framework/node version" src="https://img.shields.io/npm/v/@aries-framework/node"/>
      </a>
    </td>
  </tr>
  <tr>
    <td>@aries-framework/react-Native</td>
    <td>
      <a href="https://npmjs.com/package/@aries-framework/react-native">
        <img alt="@aries-framework/react-native version" src="https://img.shields.io/npm/v/@aries-framework/react-native"/>
      </a>
    </td>
  </tr>
</table>

## Getting Started

### Platform Specific Setup

In order to use Aries Framework JavaScript some platform specific dependencies and setup is required. See our guides below to quickly set up you project with Aries Framework JavaScript for NodeJS, React Native and Electron.

- [React Native](/docs/setup-react-native.md)
- [NodeJS](/docs/setup-nodejs.md)
- [Electron](/docs/setup-electron.md)

### Usage

Now that your project is setup and everything seems to be working, it is time to start building! Follow these guides below to get started!

0. [Overview](/docs/getting-started/overview.md)
1. [Agent](/docs/getting-started/0-agent.md)
2. [Transports](/docs/getting-started/1-transports.md)
3. [Connections](/docs/getting-started/2-connections.md)
4. [Routing](/docs/getting-started/3-routing.md)
5. [Ledger](/docs/getting-started/4-ledger.md)
6. [Credentials](/docs/getting-started/5-credentials.md)
7. [Proofs](/docs/getting-started/6-proofs.md)
8. [Logging](/docs/getting-started/7-logging.md)

## Contributing

If you would like to contribute to the framework, please read the [Framework Developers README](/DEVREADME.md) and the [CONTRIBUTING](/CONTRIBUTING.md) guidelines. These documents will provide more information to get you started!

The Aries Framework JavaScript call takes place every week at Thursday, 14:00 UTC via [Zoom](https://zoom.us/j/92215586249?pwd=Vm5ZTGV4T0cwVEl4blh3MjBzYjVYZz09). This meeting is for contributors to groom and plan the backlog, and discuss issues. Feel free to join!

## License

Hyperledger Aries Framework JavaScript is licensed under the [Apache License Version 2.0 (Apache-2.0)](/LICENSE).
