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
def gerarPQ(bits): # para esse projeto, bits será sempre igual a 1024
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

"""
a função oaep recebe uma string com o texto claro que será processado, e então o divide em blocos de no máximo 190 bytes e realiza o esquema de padding em 
    cada um desses blocos, para que eles possam ser corretamente criptografados pelo RSA. Sendo que todos os blocos processados são retornados em uma lista

em específico, o OAEP implementado utiliza os seguintes valores:
- hLen = 32: tamanho em bytes do output da Hash
- k = 256: tamanho em bytes do módulo n do RSA
- mLen = k - 2*hLen - 2 = 190 (ou menos): tamanho em bytes da mensagem
- PSlen = k - mLen - 2*hLen - 2: tamanho em bytes do padding de zeros para o DB
"""
def oaepEncrypt(message):
    message_bytes = message.encode("utf-8")

    listMsg, resultListEM = [], []
    sizeCount = 0

    while len(message_bytes) > sizeCount+190:
        temp = message_bytes[sizeCount:sizeCount+190]
        listMsg.append(temp)
        sizeCount += 190
    lastM = message_bytes[sizeCount:]
    listMsg.append(lastM)

    hashL = SHA256.new()
    hashL.update(b"") # 32 bytes de hash da label

    for msg in listMsg:
        PS = bytes([0x00] * (256 - len(msg) - (2*32) - 2))
        DB = hashL.digest() + PS + bytes([0x01]) + msg

        print(DB)

        seed = random.getrandbits(256)
        seedBytes = seed.to_bytes(32,'big')

        dbMask = MGF1(seedBytes, 223, SHA256) #Crypto.Signature.pss.MGF1(mgfSeed, maskLen, hash_gen)
        DBXor = bytes([intDB ^ intDBMask for intDB, intDBMask in zip(DB, dbMask)]) # para o XOR funcionar é necessário tratar os bytes como int

        seedMask = MGF1(DBXor, 32, SHA256)
        seedXor = bytes([intSeedBytes ^ intSeedMask for intSeedBytes, intSeedMask in zip(seedBytes, seedMask)]) 

        EM = bytes([0x00]) + seedXor + DBXor
        resultListEM.append(EM)

    return resultListEM

def oaepDecrypt(cList):
    hashLBase = SHA256.new()
    hashLBase.update(b"") # 32 bytes de hash da label

    tempListM, msgList = [], []
    resultMessage = ""

    for crypt in cList:
        maskedSeed = crypt[1:33]
        maskedDB = crypt[33:]

        seedMask = MGF1(maskedDB, 32, SHA256)
        seedBytes = bytes([intMaskedSeed ^ intSeedMask for intMaskedSeed, intSeedMask in zip(maskedSeed, seedMask)])

        dbMask = MGF1(seedBytes, 223, SHA256)

        DB = bytes([intMaskedDB ^ intDBMask for intMaskedDB, intDBMask in zip(maskedDB, dbMask)])
        
        hashL = DB[:32]
        b = DB[32]
        count = 32
        while b == 0x00 or b == 0x01:
            count += 1
            b = DB[count]
            
        msgList.append(DB[count:])

    for msg in msgList:
        resultMessage += msg.decode("utf-8")

    return resultMessage


def rsaEncrypt(mList, n, e):
    resultListC = []
    for mBytes in mList:
        mNum = int.from_bytes(mBytes, "big")
        #print(mNum)

        cNum = pow(mNum, e, n)
        #print(cNum)

        resultListC.append(cNum)
    return resultListC
    
def rsaDecrypt(cList, n, d):
    resultListM = []
    for cNum in cList:
        mNum = pow(cNum, d, n)
        #print(cNum)
        #print(mNum)

        mBytes = mNum.to_bytes(256, 'big')

        resultListM.append(mBytes)
    return resultListM

# FLUXO PRINCIPAL

# gera p e q e confere a primalidade
p, q = gerarPQ(1024)
while not (MillerRabin(p) and MillerRabin(q)): # gera p e q novamente, caso um ou outro não seja primo
    print("erro na geração de p e q, tentando novamente...")
    p, q = gerarPQ(1024)

print(f"p: {p}")
print(f"q: {q}")

n, e, d = gerarChaves(p, q)

print(f"n: {n}")
print(f"e: {e}")
print(f"d: {d}")


message = "Minha terra tem palmeiras Onde canta o Sabiá, As aves, que aqui gorjeiam, Não gorjeiam como lá. Nosso céu tem mais estrelas, Nossas várzeas têm mais flores, Nossos bosques têm mais vida, Nossa vida mais amores. Em cismar, sozinho, à noite, Mais prazer encontro eu lá; Minha terra tem palmeiras, Onde canta o Sabiá. Minha terra tem primores, Que tais não encontro eu cá; Em cismar – sozinho, à noite – Mais prazer encontro eu lá; Minha terra tem palmeiras, Onde canta o Sabiá. Não permita Deus que eu morra, Sem que eu volte para lá; Sem que desfrute os primores Que não encontro por cá; Sem qu’inda aviste as palmeiras, Onde canta o Sabiá."

resEncryptOAEP = oaepEncrypt(message)

print("resEncryptOAEP:")
print(resEncryptOAEP)

resEncryptRSA = rsaEncrypt(resEncryptOAEP, n, e)

print("resEncryptRSA:")
print(resEncryptRSA)

resDecryptRSA = rsaDecrypt(resEncryptRSA, n, d)

print("resDecryptRSA:")
print(resDecryptRSA)

resDecryptOAEP = oaepDecrypt(resDecryptRSA)

print("resDecryptOAEP:")
print(resDecryptOAEP)

print("message:")
print(message)

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
