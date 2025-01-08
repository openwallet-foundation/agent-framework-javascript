<p align="center">
  <br />
  <img
    alt="Credo Logo"
    src="https://github.com/openwallet-foundation/credo-ts/blob/c7886cb8377ceb8ee4efe8d264211e561a75072d/images/credo-logo.png"
    height="250px"
  />
</p>
<h1 align="center"><b>Credo Action Menu Module</b></h1>
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
    <a href="https://www.npmjs.com/package/@credo-ts/action-menu"
    ><img
      alt="@credo-ts/action-menu version"
      src="https://img.shields.io/npm/v/@credo-ts/action-menu"
  /></a>

</p>
<br />

Action Menu module for [Credo](https://github.com/openwallet-foundation/credo-ts.git). Implements [Aries RFC 0509](https://github.com/hyperledger/aries-rfcs/blob/1795d5c2d36f664f88f5e8045042ace8e573808c/features/0509-action-menu/README.md).

### Quick start

In order for this module to work, we have to inject it into the agent to access agent functionality. See the example for more information.

### Example of usage

```ts
import { ActionMenuModule } from '@credo-ts/action-menu'

const agent = new Agent({
  config: {
    /* config */
  },
  dependencies: agentDependencies,
  modules: {
    actionMenu: new ActionMenuModule(),
    /* other custom modules */
  },
})

await agent.initialize()

// To request root menu to a given connection (menu will be received
// asynchronously in a ActionMenuStateChangedEvent)
await agent.modules.actionMenu.requestMenu({ connectionId })

// To select an option from the action menu
await agent.modules.actionMenu.performAction({
  connectionId,
  performedAction: { name: 'option-1' },
})
```
