import random
from sympy import isprime, nextprime
import base64
import sys
from Cryptodome.Signature.pss import MGF1
from Cryptodome.Hash import SHA256

def gerar_p_q(bits):
    p = random.getrandbits(bits)
    p |= (1 << (bits - 1)) 
    p |= 1
    p = nextprime(p)  
    return (p, nextprime(p+1))  

p, q = gerar_p_q(1024)

print(f"p: {p}")
print(f"q: {q}")

message = "Minha terra tem palmeiras Onde canta o Sabiá, As aves, que aqui gorjeiam, Não gorjeiam como lá. Nosso céu tem mais estrelas, Nossas várzeas têm mais flores, Nossos bosques têm mais vida, Nossa vida mais amores. Em cismar, sozinho, à noite, Mais prazer encontro eu lá; Minha terra tem palmeiras, Onde canta o Sabiá. Minha terra tem primores, Que tais não encontro eu cá; Em cismar – sozinho, à noite – Mais prazer encontro eu lá; Minha terra tem palmeiras, Onde canta o Sabiá. Não permita Deus que eu morra, Sem que eu volte para lá; Sem que desfrute os primores Que não encontro por cá; Sem qu’inda aviste as palmeiras, Onde canta o Sabiá."

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