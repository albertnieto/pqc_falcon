from wrapper import keypair, sign, verify

pk, sk = keypair()
print(f"Public key - size: {len(pk)}, type:{type(pk)}")
print(f"Secret key - size: {len(sk)}, type:{type(sk)}")

m = "Albert".encode("utf-8")
sig = sign(m, sk)
print(f"Signature - size: {len(sig)}, type:{type(sig)}")

m_2 = "Nieto".encode("utf-8")
verify_1 = verify(sig, m, pk)
verify_2 = verify(sig, m_2, pk)
print(f"Verification - message: {m}, result:{verify_1}")
print(f"Verification - message: {m_2}, result:{verify_2}")