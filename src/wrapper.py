import os
from cffi import FFI

# Foreign Function Interface for Python. 
# Interact with almost any C code from Python, 
# based on C-like declarations that you can often copy-paste 
# from header files or documentation.
# https://cffi.readthedocs.io/en/stable/

ffi = FFI()

# First, ensure you have gcc installed. Then compile the library in the terminal:
# gcc -shared -o libfalcon.so -fPIC *.c

# Define C functions and constants
ffi.cdef("""
#define PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES   1281
#define PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES   897
#define PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES            752
#define PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_BYTES      666

int PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(
    uint8_t *pk, uint8_t *sk);

int PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(
    uint8_t *sig, size_t *siglen,
    const uint8_t *m, size_t mlen, const uint8_t *sk);

int PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen, const uint8_t *pk);

int PQCLEAN_FALCON512_CLEAN_crypto_sign(
    uint8_t *sm, size_t *smlen,
    const uint8_t *m, size_t mlen, const uint8_t *sk);

int PQCLEAN_FALCON512_CLEAN_crypto_sign_open(
    uint8_t *m, size_t *mlen,
    const uint8_t *sm, size_t smlen, const uint8_t *pk);
         """)

# If there are issues loading the shared library, 
# print the current working directory to help diagnose the problem.
# print("Current working directory:", os.getcwd())
# print(os.getcwd())

# load compiled shared library
libfalcon_path = os.getenv('LIBFALCON_PATH', './src/pqc_falcon/libfalcon.so')
falcon = ffi.dlopen(libfalcon_path)

# falcon constants
KEYS_TYPE = "uint8_t[]"
PUBLIC_KEY_BYTES = falcon.PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES
SECRET_KEY_BYTES = falcon.PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES
SIGNATURE_BYTES = falcon.PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES
SIGNATURE_LENGTH = "size_t *"
PADDED_BYTES = falcon.PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_BYTES

# falcon functions
ffi_keypair = falcon.PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair
ffi_signature = falcon.PQCLEAN_FALCON512_CLEAN_crypto_sign_signature
ffi_verify = falcon.PQCLEAN_FALCON512_CLEAN_crypto_sign_verify

def keypair() -> tuple[bytes, bytes]:
    """
    Generate a new public and secret key pair.

    Returns:
    tuple: A tuple containing the public key (bytes) and the secret key (bytes).

    Raises:
    RuntimeError: If keypair generation fails.
    """
    pk = ffi.new("uint8_t[]", PUBLIC_KEY_BYTES)
    sk = ffi.new("uint8_t[]", SECRET_KEY_BYTES)

    if ffi_keypair(pk, sk) != 0:
        raise RuntimeError("Keypair generation failed")
    
    return bytes(ffi.buffer(pk)), bytes(ffi.buffer(sk))

def sign(m: bytes, sk: bytes) -> bytes:
    """
    Sign a message using the secret key.

    Parameters:
    m (bytes): The message to be signed.
    sk (bytes): The secret key used to sign the message.

    Returns:
    signature (bytes): The signature of the message.
    """
    sig = ffi.new("uint8_t[]", SIGNATURE_BYTES)
    siglen = ffi.new("size_t *")
    m_c = ffi.new("uint8_t[]", m)

    if ffi_signature(sig, siglen, m_c, len(m), sk) != 0:
        raise RuntimeError("Signing failed")
    
    return bytes(ffi.buffer(sig, siglen[0]))

def verify(sig: bytes, m: bytes, pk: bytes) -> bool:
    """
    Verify a signed message using the public key.

    Parameters:
    sig (bytes): The signature to be verified.
    m (bytes): The message that was signed.
    pk (bytes): The public key used to verify the signature.

    Returns:
    bool: True if the signature is valid, False otherwise.
    """
    if ffi_verify(sig, len(sig), m, len(m), pk) != 0:
        return False
    return True