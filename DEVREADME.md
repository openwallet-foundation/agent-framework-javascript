# Framework Developers

This file is intended for developers working on the internals of the framework. If you're just looking how to get started with the framework, see the [docs](./docs)

# Environment Setup

## VSCode devContainer

This project comes with a [.devcontainer](./devcontainer) to make it as easy as possible to setup your dev environment and begin contributing to this project.

All the [environment variables](https://code.visualstudio.com/remote/advancedcontainers/environment-variables) noted below can be added to [devcontainer.env](./devcontainer.env) and exposed to the development docker container.

When running in a container your project root directory will be `/work`. Use this to correctly path any environment variables, for example:

```console
GENESIS_TXN_PATH=/work/network/genesis/local-genesis.txn
```

## Running tests

Test are executed using jest. E2E tests (ending in `.e2e.test.ts`) require the **indy ledger**, **cheqd ledger** or **postgres database** to be running.

When running tests that require a connection to the indy ledger pool, you can set the `TEST_AGENT_PUBLIC_DID_SEED`, `ENDORSER_AGENT_PUBLIC_DID_SEED` and `GENESIS_TXN_PATH` environment variables.

### Quick Setup

To quickly set up all services needed to run tests (Postgres, Hyperledger Indy Ledger, and Cheqd Ledger), run the following command:

```sh
docker compose up -d
```

If you're running on an ARM based machine (such as Apple Silicon), you can use the `docker-compose.arm.yml` file instead:

```sh
docker compose -f docker-compose.arm.yml up -d
```

### Run all tests

You can run all unit tests (which **do not** require the docker services to be running) using the following command.

```sh
pnpm test:unit
```

To run the e2e tests:

```sh
pnpm test:e2e
```

You can also run **all** tests:

```sh
pnpm test
```

### Setting environment variables

If you're using the setup as described in this document, you don't need to provide any environment variables as the default will be sufficient.

- `GENESIS_TXN_PATH`: The path to the genesis transaction that allows us to connect to the indy pool.
  - `GENESIS_TXN_PATH=network/genesis/local-genesis.txn` - default. Works with the [ledger setup](#setup-indy-ledger) from the previous step.
  - `GENESIS_TXN_PATH=network/genesis/builder-net-genesis.txn` - Sovrin BuilderNet genesis.
  - `GENESIS_TXN_PATH=/path/to/any/ledger/you/like`
- `TEST_AGENT_PUBLIC_DID_SEED`: The seed to use for the public DID. This will be used to do public write operations to the ledger. You should use a seed for a DID that is already registered on the ledger.
  - If using the local or default genesis, use the same seed you used for the `add-did-from-seed` command from the [ledger setup](#setup-indy-ledger) in the previous step. (default is `000000000000000000000000Trustee9`)
  - If using the BuilderNet genesis, make sure your seed is registered on the BuilderNet using [selfserve.sovrin.org](https://selfserve.sovrin.org/) and you have read and accepted the associated [Transaction Author Agreement](https://github.com/sovrin-foundation/sovrin/blob/master/TAA/TAA.md). We are not responsible for any unwanted consequences of using the BuilderNet.
- `ENDORSER_AGENT_PUBLIC_DID_SEED`: The seed to use for the public Endorser DID. This will be used to endorse transactions. You should use a seed for a DID that is already registered on the ledger.
  - If using the local or default genesis, use the same seed you used for the `add-did-from-seed` command from the [ledger setup](#setup-indy-ledger) in the previous step. (default is `00000000000000000000000Endorser9`)
  - If using the BuilderNet genesis, make sure your seed is registered on the BuilderNet using [selfserve.sovrin.org](https://selfserve.sovrin.org/) and you have read and accepted the associated [Transaction Author Agreement](https://github.com/sovrin-foundation/sovrin/blob/master/TAA/TAA.md). We are not responsible for any unwanted consequences of using the BuilderNet.
