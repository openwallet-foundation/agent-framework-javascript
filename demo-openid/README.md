<h1 align="center"><b>DEMO</b></h1>

This is the Credo OpenID4VC demo. Walk through the Credo flow yourself together with agents Alice and Faber.

Alice, a former student of Faber College, connects with the College, is issued a credential about her degree and then is asked by the College for a proof.

## Features

- ✅ Issuing a credential.
- ✅ Resolving a credential offer.
- ✅ Accepting a credential offer.
- ✅ Requesting a credential presentation.
- ✅ Resolving a presentation request.
- ✅ Accepting a resolved presentation request.

## Getting Started

### Platform Specific Setup

In order to run the Credo demo, you need to make sure you have Node.JS and PNPM installed. See the [Credo Prerequisites](https://credo.js.org/guides/getting-started/prerequisites) for more information.

### Run the demo

These are the steps for running the Credo OpenID4VC demo:

Clone the Credo git repository:

```sh
git clone https://github.com/openwallet-foundation/credo-ts.git
```

Open three different terminals next to each other and in both, go to the demo folder:

```sh
cd credo-ts/demo-openid
```

Install the project in one of the terminals:

```sh
pnpm install
```

In the first terminal run the Issuer:

```sh
pnpm issuer
```

In the second terminal run the Holder:

```sh
pnpm holder
```

In the last terminal run the Verifier:

```sh
pnpm verifier
```

### Usage

To create a credential offer:

- Go to the Issuer terminal.
- Select `Create a credential offer`.
- Select `UniversityDegreeCredential`.
- Now copy the content INSIDE the quotes (without the quotes).

To resolve and accept the credential:

- Go to the Holder terminal.
- Select `Resolve a credential offer`.
- Paste the content copied from the credential offer and hit enter.
- Select `Accept the credential offer`.
- You have now stored your credential.

To create a presentation request:

- Go to the Verifier terminal.
- Select `Request the presentation of a credential`.
- Select `UniversityDegreeCredential`.
- Copy the presentation request string content, without the quotes.

To resolve and accept the presentation request:

- Go to the Holder terminal.
- Select `Resolve a proof request`.
- Paste the copied string (without the quotes).
- Hit enter: You should see a Green message saying what will be presented.
- Select `Accept presentation request`.
- The presentation should be sent (WIP).

Exit:

- Select 'exit' to shutdown the program.

Restart:

- Select 'restart', to shutdown the current program and start a new one
