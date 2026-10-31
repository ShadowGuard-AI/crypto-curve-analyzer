![Banner](banner.png)

# crypto-curve-analyzer
Reports elliptic curve parameters (name, key size, and group order) for one of seven named curves or for the curve of an operator supplied PEM key file. With a key file it can also report a prime order note for that curve and write out the public key. It does not produce a weakness verdict and does not import custom curve definitions. - Focused on Basic cryptographic operations

## Install
`git clone https://github.com/ShadowStrikeHQ/crypto-curve-analyzer`

## Usage
`./crypto-curve-analyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `--verbose`: Enable verbose output for debugging.
- `--check-small-subgroup`: Report the prime order note for the curve of a PEM key file. Requires a key file; not applicable on a named curve run without one.
- `--output-public-key`: Output public key in PEM format to the specified file. Requires a key file; not applicable on a named curve run without one.

## License
Copyright (c) ShadowStrikeHQ
