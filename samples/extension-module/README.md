<h1 align="center"><b>Extension module example</b></h1>

This example shows how an extension module can be written and injected to an Credo `Agent` instance. Its structure is similar to the one of regular modules, although is not strictly needed to follow it to achieve this goal.

An extension module could be used for different purposes, such as storing data in an Identity Wallet, supporting custom protocols over Didcomm or implementing new [Aries RFCs](https://github.com/hyperledger/aries-rfcs/tree/main/features) without the need of embed them right into Credo's Core package. Injected modules can access to other core modules and services and trigger events, so in practice they work much in the same way as if they were included statically.

> **Note** the custom module API is in heavy development and can have regular breaking changes. This is an experimental feature, so use it at your own risk. Over time we will provide a stable API for extension modules.

## Dummy module

This example consists of a module that implements a very simple request-response protocol called Dummy. In order to do so and be able to be injected into an Credo instance, some steps were followed:

- Define Dummy protocol message classes (inherited from `AgentMessage`)
- Create handlers for those messages (inherited from `MessageHandler`)
- Define records (inherited from `BaseRecord`) and a singleton repository (inherited from `Repository`) for state persistance
- Define events (inherited from `BaseEvent`)
- Create a singleton service class that manages records and repository, and also trigger events using Agent's `EventEmitter`
- Create a singleton api class that registers handlers in Agent's `Dispatcher` and provides a simple API to do requests and responses, with the aid of service classes and Agent's `MessageSender`
- Create a module class that registers all the above on the dependency manager so it can be be injected from the `Agent` instance, and also register the features (such as protocols) the module adds to the Agent.

## Usage

In order to use this module, you first need to register `DummyModule` on the `Agent` instance. This can be done by adding an entry for it in `AgentOptions`'s modules property:

```ts
import { DummyModule } from './dummy'

// Register the module with it's dependencies
const agent = new Agent({
  config: {
    /* config */
  },
  dependencies: agentDependencies,
  modules: {
    dummy: new DummyModule({
      /* module config */
    }),
    /* other custom modules */
  },
})

await agent.initialize()
```

Then, Dummy module API methods can be called from `agent.modules.dummy` namespace, and events listeners can be created:

```ts
agent.events.on(DummyEventTypes.StateChanged, async (event: DummyStateChangedEvent) => {
  if (event.payload.dummyRecord.state === DummyState.RequestReceived) {
    await agent.modules.dummy.respond(event.payload.dummyRecord)
  }
})

const record = await agent.modules.dummy.request(connection)
```

## Run demo

This repository includes a demonstration of a requester and a responder controller using this module to exchange Dummy protocol messages. For environment set up, make sure you followed the [Credo Prerequisites](https://credo.js.org/guides/getting-started/prerequisites).

These are the steps for running it:

Clone the Credo git repository:

```sh
git clone https://github.com/openwallet-foundation/credo-ts.git
```

Open two different terminals and go to the extension-module directory:

```sh
cd credo-ts/samples/extension-module
```

Install the project in one of the terminals:

```sh
pnpm install
```

In that terminal run the responder:

```sh
pnpm responder
```

Wait for it to finish the startup process (i.e. logger showing 'Responder listening to port ...') and run requester in another terminal:

```sh
pnpm requester
```

If everything goes right, requester will connect to responder and, as soon as connection protocol is finished, it will send a Dummy request. Responder will answer with a Dummy response and requester will happily exit.
