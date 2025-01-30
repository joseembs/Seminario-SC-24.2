import random
from sympy import nextprime
import base64
import sys
from Cryptodome.Signature.pss import MGF1
from Cryptodome.Hash import SHA256

# FUNÇÕES

"""
a função gerar_p_q recebe o número de bits desejados e retorna 2 números primos, p e q, com essa quantidade de bits
"""
def gerar_p_q(bits): # para esse projeto, bits será sempre igual a 1024
    r = random.getrandbits(bits) # gera um número aleatório r com 1024 bits
    r |= (1 << (bits - 1)) # garante que o 1024º bit de r será 1
    r |= 1 # garante que r será ímpar
    p = nextprime(r)

    s = random.getrandbits(bits+1) # gera um número aleatório s com 1025 bits
    s |= (1 << (bits)) # garante que o 1025º bit de s será 1
    s |= 1 # garante que s será ímpar
    q = nextprime(s)

    return (p, q) # retorna as chaves primas p e q

"""
as funções primo e MillerRabin trabalham em conjunto para fazer o teste de primalidade de Miller-Rabin para um número n
"""
def primo(n, b): # n = ímpar maior ou igual a 3, b = base aleatória
    # encontra q ímpar tal que n-1 = q*(2^k)
    q = n-1
    k = 0
    while q % 2 == 0:
        q //= 2
        k += 1

    x = pow(b, q, n)

    # se b^q é congruente com 1 mod n, n é primo
    if x == 1:
        return True
    
    # se x não for 1
    # tenta encontrar um inteiro i tal que b^(q*2^i) é congruente com -1 mod n
    for i in range(k):
        if x == n-1:
            return True
        x *= x
        x %= n
    
    # se não encontrar, n é composto
    return False

def MillerRabin(n, reps=40): # 40 é o número default de repetições, mas pode ser passado como argumento se o usuário quiser
    if n < 3 or n%2 == 0:
        return False
    
    # se n for ímpar maior ou igual a 3, faz o teste
    for i in range(reps):
        b = random.randint(2, n-1)
        if not primo(n, b):
            return False
    return True 

"""
a função gerarChaves recebe os números p e q definidos anteriormente e retorna:
- o módulo público n
- o expoente público e
- o expoente privado d
para realizar a criptografia RSA
"""
def gerarChaves(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537 # o primo mais comumente utilizado para RSA
    d = pow(e, -1, phi)
    return (n, e, d)

# FLUXO PRINCIPAL

# gera p e q e confere a primalidade
p, q = gerar_p_q(1024)
while not (MillerRabin(p) and MillerRabin(q)): # gera p e q novamente, caso um ou outro não seja primo
    print("erro na geração de p e q, tentando novamente...")
    p, q = gerar_p_q(1024)

print(f"p: {p}")
print(f"q: {q}")

message = "Minha terra tem palmeiras Onde canta o Sabiá, As aves, que aqui gorjeiam, Não gorjeiam como lá. Nosso céu tem mais estrelas, Nossas várzeas têm mais flores, Nossos bosques têm mais vida, Nossa vida mais amores. Em cismar, sozinho, à noite, Mais prazer encontro eu lá; Minha terra tem palmeiras, Onde canta o Sabiá. Minha terra tem primores, Que tais não encontro eu cá; Em cismar – sozinho, à noite – Mais prazer encontro eu lá; Minha terra tem palmeiras, Onde canta o Sabiá. Não permita Deus que eu morra, Sem que eu volte para lá; Sem que desfrute os primores Que não encontro por cá; Sem qu’inda aviste as palmeiras, Onde canta o Sabiá."

# realiza o OAEP
message_bytes = message.encode("utf-8")
print(len(message_bytes)) #sys.getsizeof(message_bytes)

listDB = []
sizeCount = 0

while len(message_bytes) > sizeCount+128:
    temp = message_bytes[sizeCount:sizeCount+128]
    print(len(temp))
    listDB.append(temp)
    sizeCount += 128

lastM = message_bytes[sizeCount:]

if len(lastM) < 128:
    lastM += bytes([0x01])
    lastM += bytes([0x00] * (128-len(lastM))) 

print(len(lastM))
listDB.append(lastM)

print(listDB)

resultsOAEP = []

for DB in listDB:
    seed = random.getrandbits(1024)
    seedBytes = seed.to_bytes(128,'big')

    seedMGF = MGF1(seedBytes, 128, SHA256) #Crypto.Signature.pss.MGF1(mgfSeed, maskLen, hash_gen)

    DBXor = bytes([intDB ^ intSeedMGF for intDB, intSeedMGF in zip(DB, seedMGF)]) # para o XOR funcionar é necessário tratar os bytes como int

    dbMGF = MGF1(DBXor, 128, SHA256)

    seedXor = bytes([intSeedBytes ^ intDBMGF for intSeedBytes, intDBMGF in zip(seedBytes, dbMGF)]) 

    result = DBXor + seedXor + bytes([0x00])

    resultsOAEP.append(result)

print(resultsOAEP)
    

# string = "Teste"
# byte_string = string.encode("utf-8")

# byte_base64 = base64.b64encode(byte_string)
# string_base64 = byte_base64.decode("utf-8")

# byte_result = base64.b64decode(byte_base64)
# string_result = byte_result.decode("utf-8")

# print(string)
# print(string_base64)
# print(string_result)



# from Cryptodome.Cipher import PKCS1_OAEP
# from Cryptodome.PublicKey import RSA

# message = b'You can attack now!'
# key = RSA.generate(1024)
# print(key)
# cipher = PKCS1_OAEP.new(key)
# ciphertext = cipher.encrypt(message)
# print(ciphertext)
