from binteger import Bin
from circkit.boolean import OptBooleanCircuit as BooleanCircuit
#from circkit.boolean import BooleanCircuit
from wbkit.ciphers.aes import BitAES
from wbkit.ciphers.aes.aes import encrypt


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
prng = NFSR(
    taps=[0, 7, 29, 50, 100],
    ntaps=[[2, 77]],
    state=pt,
    clocks_initial=333,
    clocks_per_step=2,
)
rand = Pool(prng=prng, n=150).step

v = 0
for i in range(100):
    v ^= rand()
C.add_output(v)
C.in_place_remove_unused_nodes()
C.print_stats()





# from wbkit.serialize import RawSerializer
# RawSerializer().serialize_to_file(C, "circuits/aes10.bin")


# from wbkit.fastcircuit import FastCircuit
# C = FastCircuit("circuits/aes10.bin")
# ciphertext = C.compute_one(plaintext)
# print(ciphertext.hex())
# ciphertexts = C.compute_batch([b"my_plaintext_abc", b"anotherPlaintext"])
# print(ciphertexts)
