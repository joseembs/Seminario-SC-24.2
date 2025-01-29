import random
from sympy import isprime, nextprime
import base64

def gerar_p_q(bits):
    p = random.getrandbits(bits)
    p |= (1 << (bits - 1)) 
    p |= 1
    p = nextprime(p)  
    return (p, nextprime(p+1))  

p, q = gerar_p_q(1024)
print(f"p: {p}")
print(f"q: {q}")




string = "Teste"
byte_string = string.encode("utf-8")

byte_base64 = base64.b64encode(byte_string)
string_base64 = byte_base64.decode("utf-8")

byte_result = base64.b64decode(byte_base64)
string_result = byte_result.decode("utf-8")

print(string)
print(string_base64)
print(string_result)