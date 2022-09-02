from binteger import Bin
from circkit.boolean import OptBooleanCircuit as BooleanCircuit
#from circkit.boolean import BooleanCircuit
from wbkit.ciphers.aes import BitAES
from wbkit.ciphers.aes.aes import encrypt


C = BooleanCircuit(name="AES")

key = b"abcdefghABCDEFGH"
plaintext = b"0123456789abcdef"

key_bits = Bin(key).tuple
pt_bits = Bin(plaintext).tuple

pt = C.add_inputs(128)

ct, k10 = BitAES(pt, key_bits, rounds=10)

C.add_output(ct)

C.print_stats()

ct = C.evaluate(pt_bits)
ct = Bin(ct).bytes
print(ct.hex())

ct2 = encrypt(plaintext, key, 10)
print(ct2.hex())
print()
