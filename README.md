![The empty house at the midnight matinee: the projector reel turning at the right, its beam crossing rows of empty seat backs with dust hanging in the light, one usher torch resting dark on an armrest, and the screen lit and blank, with no lettering anywhere](intro-banner.png)

# crypto-curve-analyzer

Title block: the name above is set in Big Shoulders Stencil Text in lamp amber on nightwatch indigo, ruled beneath with a film strip, with a small reel plate beside this first heading only.

![One film reel flat and upright in nightwatch indigo edged in lamp amber, five round windows cut in the plate, one strip of film across the lowest window hanging in a short tail, the centre hub in ink black, and the name crypto-curve-analyzer lettered beneath in a cue sheet hand](logo.png)

![Through the booth window over empty seats: the projector at the right with its beam cutting left across the dark to a lit blank screen, dust in the beam, and reel cans stacked at the left with crypto-curve-analyzer pencilled on the top can lid as the only lettering in the room](banner.png)

![The booth in three bands: the lit blank screen dimming once and slowly, the reel turning at an even pace with film stepping through the gate and dust drifting in the beam, and the reel cans and cue sheet on the booth shelf held still](scene.svg)

![Major separator](sep-heavy.svg)


# crypto-curve-analyzer
Reports elliptic curve parameters (name, key size, and group order) for one of seven named curves or for the curve of an operator supplied PEM key file. With a key file it can also report a prime order note for that curve and write out the public key. It does not produce a weakness verdict and does not import custom curve definitions. - Focused on Basic cryptographic operations

> Cue slip note: the install line in the preserved record points to the wrong organisation. It is printed as it stands and flagged here, not corrected.

![Minor separator](sep-light.svg)

## Install
`git clone https://github.com/ShadowStrikeHQ/crypto-curve-analyzer`

> Cue slip note: the usage line in the preserved record is a placeholder the parser does not accept. The accepted line restores the required positional: python3 main.py CURVE_NAME_OR_KEY_FILE.

![Minor separator](sep-light.svg)

## Usage
`./crypto-curve-analyzer [params]`

> Cue slip note: the parameter list in the preserved record never names the required positional CURVE_NAME_OR_KEY_FILE, restored here from the parser. One argument must be a curve name or a PEM key file path, and the file test decides which branch runs.

![Minor separator](sep-light.svg)

## Parameters
- `-h`: Show help message and exit
- `--verbose`: Enable verbose output for debugging.
- `--check-small-subgroup`: Report the prime order note for the curve of a PEM key file. Requires a key file; not applicable on a named curve run without one.
- `--output-public-key`: Output public key in PEM format to the specified file. Requires a key file; not applicable on a named curve run without one.

> Cue slip note: the licence line in the preserved record carries the same wrong organisation as the install line. It is printed as it stands and flagged here, not corrected. A further note belongs on this slip: no verdict is given anywhere in a run.

![Minor separator](sep-light.svg)

## License
Copyright (c) ShadowStrikeHQ

![Major separator](sep-heavy.svg)

## Facts from the code, stated in the prose

This record names: secp256r1, secp256k1, secp384r1, secp521r1, brainpoolP256r1, brainpoolP384r1, brainpoolP512r1, CURVE_NAME_OR_KEY_FILE, python3 main.py CURVE_NAME_OR_KEY_FILE, --verbose, --check-small-subgroup, --output-public-key, PEM, prime order, group order, key size, git clone https://github.com/ShadowStrikeHQ/crypto-curve-analyzer, ./crypto-curve-analyzer [params], Copyright (c) ShadowStrikeHQ, MIT License, Report the Curve Parameters, Seven Named Curves, No Others, Load a PEM Key File, Show the Prime Order Note, Write the Public Key to a File, Show Help, A Name, a Size, an Order, The Note Is About the Curve, Not the Key, No Verdict Is Given.
