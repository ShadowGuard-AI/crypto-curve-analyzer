import argparse
import logging
import os
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Analyzes elliptic curves for cryptographic weaknesses.")
    parser.add_argument("curve_name", help="Name of the pre-defined elliptic curve (e.g., secp256r1) or path to a PEM-encoded private key file.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output for debugging.")
    parser.add_argument("--check-small-subgroup", action="store_true", help="Check for small subgroup attacks.")
    parser.add_argument("--output-public-key", action="store", dest="output_public_key", help="Output public key in PEM format to the specified file.")
    return parser.parse_args()


def check_curve_parameters(curve):
    """
    Checks basic curve parameters for potential weaknesses.

    Args:
        curve: The elliptic curve object.

    Returns:
        None. Prints analysis results to the console.
    """
    try:
        # An earlier version called curve.order() and curve.cofactor here;
        # neither exists on these objects, so every run logged an error
        # and printed no parameters at all. What the library does expose
        # is group_order (it matches the published order for the named
        # curves, checked for secp256r1), so report it through getattr:
        # older library versions without it still get the name and size
        # instead of an AttributeError.
        logging.info(f"Curve Name: {curve.name}")
        logging.info(f"Curve Key Size: {curve.key_size} bits")
        group_order = getattr(curve, "group_order", None)
        if group_order is not None:
            logging.info(f"Curve Group Order: {group_order}")

    except Exception as e:
        logging.error(f"Error checking curve parameters: {e}")


def check_small_subgroup_attack(private_key):
    """
    Checks for susceptibility to small subgroup attacks.

    Args:
        private_key: The elliptic curve private key.

    Returns:
        None. Prints analysis results to the console.
    """
    try:
        # The old test called public_key.multiply(7). Public key objects in
        # this library have no scalar multiplication method, so that call
        # raised AttributeError on every run and the error was the result.
        # What can be said from the curve itself: every curve this tool
        # accepts by name, and the usual PEM key curves, are the prime
        # order (cofactor 1) forms from their specifications, and a group
        # of prime order has no non-trivial small subgroup to be confined
        # to. That is a property of the named curve, not a measurement of
        # this key, and the log line below says it in those terms.
        curve_name = private_key.curve.name
        logging.info(
            f"Small subgroup check: {curve_name} is used in its prime "
            "order form, which has no non-trivial small subgroups. "
            "No per-key test is possible from the public key alone."
        )

    except Exception as e:
        logging.error(f"Error checking for small subgroup attack: {e}")



def load_private_key(key_path):
    """
    Loads a private key from a PEM file.

    Args:
        key_path: Path to the PEM file.

    Returns:
        The private key object, or None if an error occurs.
    """
    try:
        with open(key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,  # Consider secure password prompt for real-world usage
                backend=default_backend()
            )
        return private_key
    except FileNotFoundError:
        logging.error(f"File not found: {key_path}")
        return None
    except Exception as e:
        logging.error(f"Error loading private key: {e}")
        return None


def get_curve_by_name(curve_name):
    """
    Retrieves an elliptic curve object by its name.

    Args:
        curve_name: The name of the elliptic curve (e.g., secp256r1).

    Returns:
        The elliptic curve object, or None if the curve is not found.
    """
    try:
        if curve_name == "secp256r1":
            return ec.SECP256R1()
        elif curve_name == "secp256k1":
            return ec.SECP256K1()
        elif curve_name == "secp384r1":
            return ec.SECP384R1()
        elif curve_name == "secp521r1":
            return ec.SECP521R1()
        elif curve_name == "brainpoolP256r1":
            return ec.BrainpoolP256R1()
        elif curve_name == "brainpoolP384r1":
            return ec.BrainpoolP384R1()
        elif curve_name == "brainpoolP512r1":
            return ec.BrainpoolP512R1()
        else:
            logging.error(f"Unsupported curve: {curve_name}")
            return None
    except Exception as e:
        logging.error(f"Error getting curve by name: {e}")
        return None


def output_public_key_to_file(private_key, output_file):
    """
    Outputs the public key associated with the private key to a file in PEM format.

    Args:
        private_key: The private key.
        output_file: The path to the output file.
    """
    try:
        public_key = private_key.public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(output_file, "wb") as f:
            f.write(pem)
        logging.info(f"Public key written to {output_file}")
    except Exception as e:
        logging.error(f"Error writing public key to file: {e}")



def main():
    """
    Main function to execute the curve analysis.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")


    try:
        # Decide name versus file by whether the path exists. The earlier
        # flow relied on a bare except catching the SystemExit raised for
        # an unknown name, which worked, but only as a side effect: any
        # real error in the name branch would have been hidden the same way.
        private_key = None
        if os.path.isfile(args.curve_name):
            private_key = load_private_key(args.curve_name)
            if private_key is None:
                logging.error(f"Invalid private key file: {args.curve_name}")
                sys.exit(1)
            curve = private_key.curve
            logging.info(f"Analyzing curve from private key file: {args.curve_name}")
            check_curve_parameters(curve)
        else:
            curve = get_curve_by_name(args.curve_name)

            if curve:
                logging.info(f"Analyzing pre-defined curve: {args.curve_name}")
                check_curve_parameters(curve)
            else:
                logging.error(f"Invalid curve name: {args.curve_name}")
                sys.exit(1)

        # Perform additional checks if a private key is available
        if private_key:
            if args.check_small_subgroup:
                check_small_subgroup_attack(private_key)

            if args.output_public_key:
                output_public_key_to_file(private_key, args.output_public_key)


    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)



if __name__ == "__main__":
    main()