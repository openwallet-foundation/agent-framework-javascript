# Setup Libindy for MacOS, with Apple Sillicon

> NOTE: If these steps do not work, or you want to do a manual install, refer to [here](https://github.com/hyperledger/indy-sdk#macos)

## prerequisites

- Homebrew
- Node (We have tested 17.0.1 and 16.8.0 and they both work, so those should be safe.)

## Step 1: Installing OpenSSL

The first thing we'll do is install OpenSSL. Since Apple replaced OpenSSL with their own version of LibreSSL, we'll need to install it. Also, we need to install a specific version of OpenSSL that is compatible with Apples architecture. After the installation, we need to link it, so that it overrides the default openssl command (we have not noticed any issues with overriding this command, but be cautious).

```sh
brew install openssl@1.1 # possibly already installed on your system

brew link openssl@1.1 --force

echo 'export PATH="/opt/homebrew/opt/openssl@1.1/bin:$PATH"' >> ~/.zshrc

source ~/.zshrc

```

To double-check if the correct version is installed, you need to restart your terminal session and run the following command:

```sh
openssl version

# OUTPUT: OpenSSL 1.1.1m  14 Dec 2021
```

## Step 2: Installing other dependencies

After installing OpenSSL, we can now install the easier dependencies by running the following command:

```sh
brew install libsodium zeromq
```

## Step 3: Installing libindy

Hyperledger provides some libindy build, but the one for Apple is built for intel x86_64. We have built libindy for Apple architecture, arm64, and is located [here](https://drive.google.com/file/d/1JaRqAEAyodjeh120YYZ0t42zfhN3wHiW/view).
Download this file and extract in this precise location: `/usr/local/lib/libindy.dylib`
After this, execute the following command:

```sh
open /usr/local/lib/
```

This will open a new Finder window. In this window, click on `libindy.dylib` with `control + click` and click on `open`. This is a weird quirk in macOS to be able to use this file.

## Step 4: Confirm the installation

To confirm if libindy is correctly installed to be used with [Aries Framework JavaScript](https://github.com/hyperledger/aries-framework-javascript), run the following command:

```sh
npx -p @aries-framework/node is-indy-installed

# OUTPUT: Libindy was installed correctly
```

If the output was anything else then that, there might be some issues with your installation. If the only step you did the step 1 from this article, please report this [here](https://github.com/hyperledger/aries-framework-javascript/issues) with an error log.

To acquire this error log execute the following:

```sh
npm i @aries-framework/node
```
