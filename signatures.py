import random
from sympy import nextprime
import base64
import sys
from Cryptodome.Signature.pss import MGF1
from Cryptodome.Hash import SHA256
from Cryptodome.Hash import SHA3_256


# FUNÇÕES

"""
a função gerarPQ recebe o número de bits desejados e retorna 2 números primos, p e q, com essa quantidade de bits
"""
def gerarPQ(bits): # para esse projeto, bits será sempre igual a 1024
    r = random.getrandbits(bits) # gera um número aleatório r com 1024 bits
    r |= (1 << (bits - 1)) # garante que o 1024º bit de r será 1
    r |= 1 # garante que r será ímpar
    p = nextprime(r)

    q = nextprime(p+1) # q é o próximo primo diferente de p

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
a função oaepEncrypt recebe como parâmetro apenas uma string com o texto claro inicial, para que esta seja dividida em blocos codificados, de tamanho específico e 
    compatíveis com a função RSA. Para isso, a mensagem é dividida em blocos de no máximo 190 bytes e complementada com uma hash e um padding, formando o bloco DB,
    que então é mascarado por uma seed aleatória e usado para mascará-la, resultando em blocos de exatamente 256 bytes. Após realizar
    esse processo com todas as partes da mensagem, a função retorna uma lista de byte strings de todos os blocos.

em específico, o OAEP implementado utiliza os seguintes valores:
- hLen = 32: tamanho em bytes da Hash de label (Hash(L))
- k = 256: tamanho em bytes do módulo n do RSA, que também é o tamanho dos blocos gerados pelo OAEP
- mLen = k - 2*hLen - 2 = 190 (ou menos): tamanho em bytes dos blocos da mensagem
- PSlen = k - mLen - 2*hLen - 2: tamanho em bytes do padding de zeros para o DB
- DB = Hash(L)||PS||0x01||M = 223 bytes: bloco de dados que será mascarado e usado para mascarar a seed
- Seed: valor aleatório gerado pelo SHA256, de tamanho 32 bytes
- maskedSeed, maskedDB: máscaras geradas pelo XOR do DB e da Seed após serem processados pela função MGF1
- EM = 0x00||maskedSeed||maskedDB = 256 bytes: bloco de bytes resultante
"""
def oaepEncrypt(message):
    message_bytes = message.encode("utf-8") # mensagem é codificado para bytes com base no utf-8

    listMsg, resultListEM = [], []
    sizeCount = 0

    while len(message_bytes) > sizeCount+190:
        temp = message_bytes[sizeCount:sizeCount+190]
        listMsg.append(temp)
        sizeCount += 190
    lastM = message_bytes[sizeCount:] # último bloco da mensagem é o único capaz de ser menor que 190 bytes
    listMsg.append(lastM)

    hashL = SHA256.new()
    hashL.update(b"") # hash gerada ao usar uma string vazia como label

    for msg in listMsg:
        PS = bytes([0x00] * (256 - len(msg) - (2*32) - 2))
        DB = hashL.digest() + PS + bytes([0x01]) + msg

        seed = random.getrandbits(256)
        seedBytes = seed.to_bytes(32,'big')

        dbMask = MGF1(seedBytes, 223, SHA256)
        maskedDB = bytes([intDB ^ intDBMask for intDB, intDBMask in zip(DB, dbMask)]) # para o XOR funcionar é necessário tratar os bytes como int

        seedMask = MGF1(maskedDB, 32, SHA256)
        maskedSeed = bytes([intSeedBytes ^ intSeedMask for intSeedBytes, intSeedMask in zip(seedBytes, seedMask)]) 

        EM = bytes([0x00]) + maskedSeed + maskedDB
        resultListEM.append(EM)

    return resultListEM

"""
a função oaepDecrypt recebe como parâmetro uma lista de byte strings, as quais são individualmente processadas pelas etapas de decodificação do OAEP até gerar de
    volta os blocos da mensagem original. Tais etapas utilizam os tamanhos fixos das diferentes partes dos blocos gerados pelo OAEP para realizar as operações 
    inversas de cada um deles, de forma que é possível recuperar a seed, a mensagem e o hash da label utilizados, sendo que este último pode ser feito novamente
    e comparado com o recebido para verificar que não houveram modificações nesta parte.
"""
def oaepDecrypt(cList):
    hashLBase = SHA256.new()
    hashLBase.update(b"") # 32 bytes de hash da label
    hashLComp = hashLBase.digest()

    msgList = []
    resultMessage = ""
    correctCount = 0
    hashErrors = []

    for EM in cList:
        maskedSeed = EM[1:33]
        maskedDB = EM[33:]

        seedMask = MGF1(maskedDB, 32, SHA256)
        seedBytes = bytes([intMaskedSeed ^ intSeedMask for intMaskedSeed, intSeedMask in zip(maskedSeed, seedMask)])

        dbMask = MGF1(seedBytes, 223, SHA256)

        DB = bytes([intMaskedDB ^ intDBMask for intMaskedDB, intDBMask in zip(maskedDB, dbMask)]) # DB é recuperado
        
        hashL = DB[:32] # é feito o parsing do DB para separar dele a hash da label, o padding de zeros e a mensagem
        b = DB[32]
        count = 32
        while b == 0x00 or b == 0x01:
            count += 1
            b = DB[count]
            
        if hashLComp == hashL: # verificação das hashes
            correctCount += 1
            msgList.append(DB[count:])
        else:
            hashErrors.append(EM)

    print(f"Verificação das hashes de label do OAEP:\n{correctCount} hashes corretas de {len(cList)}, erro nos seguintes blocos:\n{hashErrors}\n")

    for msg in msgList:
        resultMessage += msg.decode("utf-8") # mensagem é decodificado de bytes para texto com base no utf-8

    return resultMessage

"""
a função rsaEncrypt recebe como parâmetros uma byte string, o valor 'n' (módulo público do RSA) e o valor 'd' (chave privada do remetente). Neste caso, a byte 
    string será uma hash de 32 bytes gerada ao processar um bloco vindo do OAEP, e ela será tratada como um int para ser feita a exponenciação dela pelo valor
    'd' com módulo 'n'.
"""
def rsaEncrypt(mBytes, n, d):
    mNum = int.from_bytes(mBytes, 'big')

    cNum = pow(mNum, d, n)

    return cNum.to_bytes(256, 'big')

"""
a função rsaDecrypt recebe como parâmetros uma byte string, o valor 'n' (módulo público do RSA) e o valor 'e' (chave pública do remetente). Neste ponto a byte 
    string será um valor codificado pelo RSA com a chave privada do remetente, então se a decriptação ocorrer corretamente com a chave pública do mesmo, significa
    que a assinatura dele foi confirmada.
"""
def rsaDecrypt(cBytes, n, e):
    cNum = int.from_bytes(cBytes, 'big')
    
    mNum = pow(cNum, e, n)

    return mNum.to_bytes(256, 'big')

"""
a função authEncrypt recebe a lista de byte strings gerada pelo oaepEncrypt e os valores 'n' e 'd' do RSA. Inicialmente, cada byte string tem sua hash calculada
    pelo SHA3-256, a qual então é encriptada pelo RSA (utilizando os valores 'n' e 'd') e anexada ao final da byte string original, gerando uma mensagem de 512
    bytes. Por fim, essa mensagem é codificada em Base64 e adicionada a uma lista, que é retornada pela função após todas as operações.
"""
def authEncrypt(oaepList, n, d):
    resultListAuth = []

    for msg in oaepList:
        shaObj = SHA3_256.new()
        shaObj.update(msg)
        tempSha = shaObj.digest()

        encHash = rsaEncrypt(tempSha, n, d)

        authMsg = msg + encHash

        resultListAuth.append(base64.b64encode(authMsg))

    return resultListAuth

"""
a função authDecrypt recebe uma de lista de strings codificadas em Base64 e os valores 'n' e 'd' do RSA. Cada uma das strings é decodificada do Base64 e então
    dividida na metade, com a primeira metade sendo a mensagem codificada pelo OAEP enquanto a segunda metade é a hash (da própria mensagem) encriptada pelo RSA.
    A partir disso, a hash é decriptada do RSA ao utilizar os valores 'n' e 'd' e comparada com uma nova hash, calculada da mensagem encontrada na primeira metade,
    pois caso ambas as hashes sejam iguais, significa que a mensagem foi corretamente enviada e a assinatura do remetente foi confirmada. Apesar disso, a mensagem
    ainda precisa ser reconstruída e decodificada e verificada pelo OAEP, então todos os blocos dela são adicionados a uma lista para ser retornada pela função.
"""
def authDecrypt(authList, n, d):
    resultListMsg = []
    correctCount = 0
    hashErrors = []

    for authB64 in authList:
        authMsg = base64.b64decode(authB64)
        msg = authMsg[:256]
        encHash = authMsg[256:]

        decHash = rsaDecrypt(encHash, n, d)

        shaObj = SHA3_256.new()
        shaObj.update(msg)
        testHash = shaObj.digest()

        if testHash == decHash[224:]: # verificação das hashes
            correctCount += 1
            resultListMsg.append(msg)
        else:
            hashErrors.append(authB64)

    print(f"Verificação das hashes da mensagem:\n{correctCount} hashes corretas de {len(resultListMsg)}, erro nos seguintes blocos:\n{hashErrors}\n")
        
    return resultListMsg

# FLUXO PRINCIPAL

# gera p e q e confere a primalidade
p, q = gerarPQ(1024)
while not (MillerRabin(p) and MillerRabin(q)): # gera p e q novamente, caso um ou outro não seja primo
    print("erro na geração de p e q, tentando novamente...")
    p, q = gerarPQ(1024)

print(f"Valores para o RSA:")
print(f"p: {p}")
print(f"q: {q}\n")

n, e, d = gerarChaves(p, q)

print(f"n: {n}")
print(f"e: {e}")
print(f"d: {d}\n")

readFile = open("exemplo.txt", mode="r", encoding="utf-8")
message = readFile.read()
readFile.close()

print(f"Mensagem inicial:\n{message}\n")

resEncryptOAEP = oaepEncrypt(message)

print("Blocos da mensagem após OAEP:",*resEncryptOAEP, sep="\n")
print()

resAuth = authEncrypt(resEncryptOAEP, n, e)

print("Blocos codificados e assinados, os quais seriam enviados ao destinatário da mensagem:",*resAuth, sep="\n")
print()

resCheck = authDecrypt(resAuth, n, d)

resDecryptOAEP = oaepDecrypt(resCheck)

print(f"Mensagem decifrada:\n{resDecryptOAEP}\n")

if message == resDecryptOAEP:
    print(f"R: Mensagem inicial corretamente enviada e recebida.\n")
else:
    print(f"R: Erro no envio ou na decodificação da mensagem.")
