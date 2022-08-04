# bitcoin-scripting

## Disclaimer

This is **ALPHA** software.  We make no claims to API stability or correctness.  We do encourage input from downstream users! 

## Overview

This package aims to support application developers working with miniscript, and script descriptors.  The following features are available:

* Miniscript: parser, printer, compiler, type checker, and witness calculator
* Script descriptors: parser + printer, address and script calculations

## Development

Hackage hosts our [documentation][hackage].  Be sure to click the "source" links for highlighted source code with links to definitions.  To get started with the repository:

``` bash
git clone https://github.com/bitnomial/bitcoin-scripting
cd bitcoin-scripting
cabal build && cabal test 
```

We only test builds with `GHC == 9.2.3` and we recommend using [ghcup][ghcup] to manage GHC versions.

Please format using `ormolu` (with 4 space tabs) or `fourmolu` (with default configuration).

[hackage]: https://hackage.haskell.org/package/bitcoin-scripting
[ghcup]: https://gitlab.haskell.org/haskell/ghcup
