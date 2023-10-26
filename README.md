# Simplicity QA Asset Generator


## Generate the assets

Run the main method to generate the file `script_assets_test.json`.

```bash
cargo run
```

## Build Elements Core

Clone [Elements Core](https://github.com/ElementsProject/elements) and switch to the [Simplicity branch](https://github.com/ElementsProject/elements/tree/simplicity).

```bash
git clone git@github.com:ElementsProject/elements.git
cd elements
git checkout simplicity
```

[Configure your development environment](https://github.com/ElementsProject/elements/blob/master/doc/build-unix.md). Cough, there is an [easy way using nix](https://github.com/uncomputable/bitcoin-nix-tools), cough.

Then build Elements Core.

```bash
./autogen.sh
./configure
make # use "-j N" for N parallel jobs
```

## Use the assets

First, [build Elements Core for testing](https://github.com/uncomputable/asset-gen/tree/master#build-elements-core).

Then run the unit test assets using the test runner.

```bash
DIR_UNIT_TEST_DATA=../asset-gen ./src/test/test_bitcoin --log_level=warning --run_test=script_test
```

The variable `DIR_UNIT_TEST_DATA` selects the directory in which the file `script_assets_test.json` is located.
