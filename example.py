import logging

from binteger import Bin
from circkit.boolean import OptBooleanCircuit as BooleanCircuit
#from circkit.boolean import BooleanCircuit
from wbkit.ciphers.aes import BitAES
from wbkit.ciphers.aes.aes import encrypt

logging.basicConfig(level=logging.DEBUG)


C = BooleanCircuit(name="AES")

key = b"abcdefghABCDEFGH"
plaintext = b"0123456789abcdef"

pt = C.add_inputs(128)

ct, k10 = BitAES(pt, Bin(key).tuple, rounds=10)

C.add_output(ct)
C.in_place_remove_unused_nodes()

C.print_stats()

ct = C.evaluate(Bin(plaintext).tuple)
ct = Bin(ct).bytes
print(ct.hex())

ct2 = encrypt(plaintext, key, 10)
print(ct2.hex())
print()

assert ct == ct2


from wbkit.prng import NFSR, Pool

nfsr = NFSR(
    taps=[[2, 77], [0], [7], [29], [50], [100]],
    clocks_initial=128,
    clocks_per_step=3,
)
prng = Pool(prng=nfsr, n=192)


from wbkit.masking import ISW, MINQ, DumShuf

# C = MINQ(prng=prng).transform(C)
# C.in_place_remove_unused_nodes()
# C.print_stats()

C = DumShuf(prng=prng, n_shares=3).transform(C)
C.in_place_remove_unused_nodes()
C.print_stats()

C = ISW(prng=prng, order=1).transform(C)
C.in_place_remove_unused_nodes()
C.print_stats()

ct = C.evaluate(Bin(plaintext).tuple)
ct = Bin(ct).bytes
print(ct.hex())



# from wbkit.serialize import RawSerializer
# RawSerializer().serialize_to_file(C, "circuits/aes10.bin")


# from wbkit.fastcircuit import FastCircuit
# C = FastCircuit("circuits/aes10.bin")
# ciphertext = C.compute_one(plaintext)
# print(ciphertext.hex())
# ciphertexts = C.compute_batch([b"my_plaintext_abc", b"anotherPlaintext"])
# print(ciphertexts)
