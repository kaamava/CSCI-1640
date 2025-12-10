from phe import paillier
import random
import numpy as np

def compute_polynomial_coeffs(S):
    """
    Given S = {s1, ..., sn}, compute coefficients of the polynomial:
        P(x) = (x - s1)(x - s2)...(x - sn)
    Returns coefficients [a0, a1, ..., an] for:
        P(x) = a_n x^n + ... + a_1 x + a_0
    """
    poly = np.poly1d([1])

    for s in S:
        poly *= np.poly1d([1, -s])

    coeffs = poly.coeffs.astype(int).tolist()
    return coeffs

public_key, private_key = paillier.generate_paillier_keypair()

S = eval(input("Please input server's private set："))
coeffs = compute_polynomial_coeffs(S)
degree = len(coeffs) - 1

print("Polynomial coefficients a_n ... a_0:", coeffs)

c = int(input("Please input client’s private value："))

powers = [pow(c, k) for k in range(degree + 1)]

encrypted_powers = [public_key.encrypt(v) for v in powers]

encrypted_poly = public_key.encrypt(0)

coeffs_reversed = coeffs[::-1]

for a_i, enc_c_i in zip(coeffs_reversed, encrypted_powers):
    encrypted_poly += enc_c_i * a_i

r = random.randint(1, 1_000_000)
blinded_ciphertext = encrypted_poly * r
result = private_key.decrypt(blinded_ciphertext)

print("\nDecryption result:", result)
if result == 0:
    print(">>> Client concludes: c ∈ S")
else:
    print(">>> Client concludes: c ∉ S")
