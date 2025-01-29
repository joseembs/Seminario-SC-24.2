import random
from sympy import isprime, nextprime

def gerar_p_q(bits):
    p = random.getrandbits(bits)
    p |= (1 << (bits - 1)) 
    p |= 1
    p = nextprime(p)  
    return (p, nextprime(p+1))  

p, q = gerar_p_q(1024)
print(f"p: {p}")
print(f"q: {q}")
