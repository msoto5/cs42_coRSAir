import gmpy2, random
from gmpy2 import isqrt, c_div

# Genrate pubkey
from Crypto.PublicKey.RSA import construct
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

urandom = random.SystemRandom()

def get_prime(size):
    while True:
        r = urandom.getrandbits(size)
        if gmpy2.is_prime(r): # Miller-rabin
            return r

def test_key(N, e, d):
    msg = (N - 123) >> 7
    c = pow(msg, e, N)
    return pow(c, d, N) ==  msg

def create_keypair(size):
    while True:
        p = get_prime(size // 2)
        q = get_prime(size // 2)
        # Comprobando condición Wiener Attack
        if q < p < 2*q:
            break

    N = p * q
    phi_N = (p - 1) * (q - 1)

    # Recall that: d < (N^(0.25))/3
    max_d = c_div(isqrt(isqrt(N)), 3)
    max_d_bits = max_d.bit_length() - 1

    while True:
        d = urandom.getrandbits(max_d_bits)
        try:
            e = int(gmpy2.invert(d, phi_N))
        except ZeroDivisionError:
            continue
        if (e * d) % phi_N == 1:
            break
    assert test_key(N, e, d)

    return  N, e, d, p, q

if __name__ == "__main__":
    N, e, d, p, q = create_keypair(32)

    print(f"N: {N}\ne: {e}\nd: {d}\np: {p}\nq: {q}")

    # Construct pubkey
    rsaKey = construct((N, e))
    pubKey = rsaKey.publickey()

    pubKeyPEM = rsaKey.exportKey()
    print(pubKeyPEM.decode('ascii'))

    with open('my_pubkey.key', 'wb') as f:
        f.write(pubKeyPEM)

    # Construct privkey
    privKey = construct((N, e, d, p, q))
    print(privKey.has_private())

    privKeyPEM = privKey.exportKey()
    with open("my_privkey.key", 'wb') as f:
        f.write(privKeyPEM)

    print(privKeyPEM.decode('ascii'))