import ctypes,base64

lib = ctypes.CDLL("./lib.so")
uint8_t = ctypes.c_uint8
KYBER_K = 3  # 假设 KYBER_K 的值为 10
KYBER_N = 256  # 假设 KYBER_N 的值为 256
KYBER_INDCPA_PUBLICKEYBYTES =  3*384+32
KYBER_INDCPA_SECRETKEYBYTES =  3*384
KYBER_INDCPA_BYTES = 3*320+128
KYBER_INDCPA_MSGBYTES = 32
KYBER_SYMBYTES = 32
CRYPTO_PUBLICKEYBYTES = 3*384+32
CRYPTO_SECRETKEYBYTES = 3*384 + 3*384+32 + 2*32

class poly(ctypes.Structure):
    _fields_ = [("coeffs", ctypes.c_int16 * KYBER_N)]

class polyvec(ctypes.Structure):
    _fields_ = [("vec", poly * KYBER_K)]


indcpa_keypair = lib.pqcrystals_kyber768_ref_indcpa_keypair
indcpa_enc = lib.pqcrystals_kyber768_ref_indcpa_enc
indcpa_dec = lib.pqcrystals_kyber768_ref_indcpa_dec

crypto_kem_keypair = lib.pqcrystals_kyber768_ref_keypair
crypto_kem_enc = lib.pqcrystals_kyber768_ref_enc
crypto_kem_dec = lib.pqcrystals_kyber768_ref_dec


#密钥产生
my_polyvec = polyvec()
indcpa_keypair.argtypes = [ctypes.POINTER(ctypes.c_uint8),ctypes.POINTER(ctypes.c_uint8),ctypes.POINTER(polyvec)]
indcpa_keypair.restype = None

pk = (uint8_t * KYBER_INDCPA_PUBLICKEYBYTES)()
sk = (uint8_t * KYBER_INDCPA_SECRETKEYBYTES)()
skpoly = polyvec()

indcpa_keypair(pk, sk, skpoly)


#加密
indcpa_enc.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
indcpa_enc.restype = None

ciphertext = (ctypes.c_uint8 * KYBER_INDCPA_BYTES)()  # 创建一个大小为KYBER_INDCPA_BYTES的ctypes数组
message = (ctypes.c_uint8 * KYBER_INDCPA_MSGBYTES)()  # 创建一个大小为KYBER_INDCPA_MSGBYTES的ctypes数组
# base64_encoded = base64.b64encode(message).decode('utf-8')
# print(base64_encoded)

random_coins = (ctypes.c_uint8 * KYBER_SYMBYTES)()  # 创建一个大小为KYBER_SYMBYTES的ctypes数组

indcpa_enc(ciphertext, message, pk, random_coins)

# 访问输出结果
# result = bytearray(ciphertext)  # 将ctypes数组转换为字节数组
# base64_encoded = base64.b64encode(result).decode('utf-8')
# print(base64_encoded)

#解密
indcpa_dec.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
indcpa_dec.restype = None

recovered_message = (ctypes.c_uint8 * KYBER_INDCPA_MSGBYTES)()  # 创建一个大小为KYBER_INDCPA_MSGBYTES的ctypes数组

indcpa_dec(recovered_message, ciphertext, sk)

# 访问输出结果
# result = bytearray(recovered_message)  # 将ctypes数组转换为字节数组
# base64_encoded = base64.b64encode(result).decode('utf-8')
# print(base64_encoded)


#kem_keypair示例
crypto_kem_keypair.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),  # pk: unsigned char*
    ctypes.POINTER(ctypes.c_uint8),  # sk: unsigned char*
    ctypes.POINTER(polyvec)  # skpoly: polyvec*
]
crypto_kem_keypair.restype = ctypes.c_int
public_key = (ctypes.c_uint8 * CRYPTO_PUBLICKEYBYTES)()
secret_key = (ctypes.c_uint8 * CRYPTO_SECRETKEYBYTES)()
skpoly = polyvec()

crypto_kem_keypair(public_key, secret_key, ctypes.byref(skpoly))

#kem_enc示例
crypto_kem_enc.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),  # ct: unsigned char*
    ctypes.POINTER(ctypes.c_uint8),  # ss: unsigned char*
    ctypes.POINTER(ctypes.c_uint8)  # pk: const unsigned char*
]
crypto_kem_enc.restype = ctypes.c_int

ciphertext = (ctypes.c_uint8 * KYBER_INDCPA_BYTES)()
shared_secret = (ctypes.c_uint8 * KYBER_SYMBYTES)()
crypto_kem_enc(ciphertext, shared_secret, public_key)

ss_result = bytearray(shared_secret)
result = bytearray(ss_result)  # 将ctypes数组转换为字节数组
base64_encoded = base64.b64encode(result).decode('utf-8')
print(base64_encoded)

#kem_dec示例
crypto_kem_dec.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),  # ss: unsigned char*
    ctypes.POINTER(ctypes.c_uint8),  # ct: const unsigned char*
    ctypes.POINTER(ctypes.c_uint8)  # sk: const unsigned char*
]
crypto_kem_dec.restype = ctypes.c_int
out_shared_secret = (ctypes.c_uint8 * KYBER_SYMBYTES)()
# 调用函数
crypto_kem_dec(shared_secret, ciphertext, secret_key)
                      
# 访问输出结果
ss_result = bytearray(shared_secret)
result = bytearray(ss_result)  # 将ctypes数组转换为字节数组
base64_encoded = base64.b64encode(result).decode('utf-8')
print(base64_encoded)
