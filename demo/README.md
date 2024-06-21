<h1 align="center"><b>DEMO</b></h1>

This is the Credo demo. Walk through the Credo flow yourself together with agents Alice and Faber.

Alice, a former student of Faber College, connects with the College, is issued a credential about her degree and then is asked by the College for a proof.

## Features

- ✅ Creating a connection
- ✅ Offering a credential
- ✅ Requesting a proof
- ✅ Sending basic messages

## Getting Started

### Platform Specific Setup

In order to run the Credo demo, you need to make sure you have Node.JS and PNPM installed. See the [Credo Prerequisites](https://credo.js.org/guides/getting-started/prerequisites) for more information.

### Run the demo

These are the steps for running the Credo demo:

Clone the Credo git repository:

```sh
git clone https://github.com/openwallet-foundation/credo-ts.git
```

Open two different terminals next to each other and in both, go to the demo folder:

```sh
cd credo-ts/demo
```

Install the project in one of the terminals:

```sh
pnpm install
```

In the left terminal run Alice:

```sh
pnpm alice
```

In the right terminal run Faber:

```sh
pnpm faber
```

### Usage

To set up a connection:

- Select 'receive connection invitation' in Alice and 'create connection invitation' in Faber
- Faber will print a invitation link which you then copy and paste to Alice
- You have now set up a connection!

To offer a credential:

- Select 'offer credential' in Faber
- Faber will start with registering a schema and the credential definition accordingly
- You have now send a credential offer to Alice!
- Go to Alice to accept the incoming credential offer by selecting 'yes'.

To request a proof:

- Select 'request proof' in Faber
- Faber will create a new proof attribute and will then send a proof request to Alice!
- Go to Alice to accept the incoming proof request

To send a basic message:

- Select 'send message' in either one of the Agents
- Type your message and press enter
- Message sent!

Exit:

- Select 'exit' to shutdown the agent.

Restart:

- Select 'restart', to shutdown the current agent and start a new one
