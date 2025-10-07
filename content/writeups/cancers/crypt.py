from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import sys

def transform(param_1: list[int], param_2: int):
    uVar2 = (param_2 * -0x61c8864f) & 0xffffffff
    uVar5 = (param_2 << 0x10 & 0xffffffff) | (param_2 >> 0x10 & 0xffffffff);
    uVar3 = ((param_2 ^ 0xf00dabcd) << 0xb & 0xffffffff) ^ param_2 ^ 0xf00dabcd;
    uVar4 = (((0x13371346 - param_2) & 0xffffffff) * 0x800 & 0xffffffff) ^ ((0x13371346 - param_2) & 0xffffffff);
    uVar1 = (param_2 * -0x44327800 & 0xffffffff) ^ uVar2;
    uVar2 = ((uVar3 >> 8) ^ (uVar2 >> 0x13) & 0xffffffff) ^ uVar2 ^ uVar3;
    uVar5 = (uVar5 << 0xb & 0xffffffff) ^ uVar5;
    uVar6 = uVar5 >> 8 ^ uVar5 ^ uVar2;
    uVar5 = uVar2 << 0xb & 0xffffffff ^ uVar2;
    uVar7 = uVar6 ^ uVar2 >> 0x13;
    uVar3 = uVar4 >> 8 ^ uVar4 ^ uVar7;
    uVar7 = uVar7 << 0xb & 0xffffffff ^ uVar7;
    uVar2 = uVar3 ^ uVar6 >> 0x13;
    uVar4 = uVar1 >> 8 ^ uVar1 ^ uVar2;
    uVar2 = uVar2 << 0xb & 0xffffffff ^ uVar2;
    uVar3 = uVar4 ^ uVar3 >> 0x13;
    uVar1 = uVar5 >> 8 ^ uVar5 ^ uVar3;
    uVar3 = uVar3 << 0xb & 0xffffffff ^ uVar3;
    uVar4 = uVar1 ^ uVar4 >> 0x13;
    uVar5 = uVar7 >> 8 ^ uVar7 ^ uVar4;
    uVar4 = uVar4 << 0xb & 0xffffffff ^ uVar4;
    uVar1 = uVar5 ^ uVar1 >> 0x13;
    uVar2 = uVar2 >> 8 ^ uVar2 ^ uVar1;
    uVar1 = uVar1 << 0xb & 0xffffffff ^ uVar1;
    uVar5 = uVar2 ^ uVar5 >> 0x13;
    uVar6 = uVar3 >> 8 ^ uVar3 ^ uVar5;
    uVar5 = uVar5 << 0xb & 0xffffffff ^ uVar5;
    uVar7 = uVar6 ^ uVar2 >> 0x13;
    uVar3 = uVar4 >> 8 ^ uVar4 ^ uVar7;
    uVar7 = uVar7 << 0xb & 0xffffffff ^ uVar7;
    uVar2 = uVar3 ^ uVar6 >> 0x13;
    uVar4 = uVar1 >> 8 ^ uVar1 ^ uVar2;
    uVar2 = uVar2 << 0xb & 0xffffffff ^ uVar2;
    uVar3 = uVar4 ^ uVar3 >> 0x13;
    uVar1 = uVar5 >> 8 ^ uVar5 ^ uVar3;
    uVar3 = uVar3 << 0xb & 0xffffffff ^ uVar3;
    uVar5 = uVar1 ^ uVar4 >> 0x13;
    uVar7 = uVar7 >> 8 ^ uVar7 ^ uVar5;
    uVar5 = uVar5 << 0xb & 0xffffffff ^ uVar5;
    uVar1 = uVar7 ^ uVar1 >> 0x13;
    uVar4 = uVar2 >> 8 ^ uVar2 ^ uVar1;
    uVar1 = uVar1 << 0xb & 0xffffffff ^ uVar1;
    uVar2 = uVar4 ^ uVar7 >> 0x13;
    uVar7 = uVar3 >> 8 ^ uVar3 ^ uVar2;
    uVar2 = uVar2 << 0xb & 0xffffffff ^ uVar2;
    uVar4 = uVar7 ^ uVar4 >> 0x13;
    uVar3 = uVar5 >> 8 ^ uVar5 ^ uVar4;
    uVar4 = uVar4 << 0xb & 0xffffffff ^ uVar4;
    uVar5 = uVar3 ^ uVar7 >> 0x13;
    uVar7 = uVar1 >> 8 ^ uVar1 ^ uVar5;
    uVar5 = uVar5 << 0xb & 0xffffffff ^ uVar5;
    uVar6 = uVar7 ^ uVar3 >> 0x13;
    uVar1 = uVar2 >> 8 ^ uVar2 ^ uVar6;
    uVar2 = uVar1 ^ uVar7 >> 0x13;
    uVar3 = uVar4 >> 8 ^ uVar4 ^ uVar2;
    uVar1 = uVar3 ^ uVar1 >> 0x13;
    param_1[3] = (uVar5 >> 8 ^ uVar5 ^ uVar1 ^ uVar3 >> 0x13) & 0xffffffff;
    param_1[0] = uVar6 & 0xffffffff;
    param_1[1] = uVar2 & 0xffffffff;
    param_1[2] = uVar1 & 0xffffffff;
    return param_1

def prng_xor_1(state, flag):
    for i, c in enumerate(flag):
        uVar36 = state[0] << 0xb & 0xffffffff ^ state[0];
        uVar36 = uVar36 >> 8 ^ state[3] >> 0x13 ^ uVar36 ^ state[3];
        uVar40 = (uVar36 >> 0x10 ^ uVar36) * 0x45d9f3b & 0xffffffff;
        randthing = (uVar40 >> 0x10 ^ uVar40) * 0x3848f357 & 0xffffffff;
        flag[i] = flag[i] ^ ((randthing >> 0x10) & 0xff) ^ (randthing & 0xff);
        #flag_ptr = flag_ptr + 1;
        uVar40 = state[1] << 0xb  & 0xffffffff ^ state[1];
        state[0] = state[2];
        uVar40 = uVar40 >> 8 ^ uVar40 ^ uVar36;
        state[1] = state[3];
        state[3] = uVar36 >> 0x13 ^ uVar40;
        uVar40 = (uVar40 >> 0x10 ^ state[3]) * 0x45d9f3b & 0xffffffff;
        uVar40 = (uVar40 >> 0x10 ^ uVar40) * 0x3848f357 & 0xffffffff;
        state[2] = uVar36;
        state = transform(state,uVar40 & 0x7fffffff ^ uVar40 >> 0x10);
        puVar39 = len(flag);
    return flag

def prng_xor_2(rand, flag):
    for i in range(len(flag)):
        rand = ((rand * 0x343fd & 0xffffffff) + 0x269ec3) & 0xffffffff
        flag[i] = flag[i] ^ rand >> 0x10 & 0xff
    return flag, rand

flag_encrypted = open(sys.argv[1], 'rb').read()
iv = flag_encrypted[0:16]
ciphertext = flag_encrypted[16:]
print("iv=", iv.hex())

key = bytes.fromhex("f078177e309d2f74d32e571c3b14434ba9d9d9d90958bf208c5a4241a670daaa")
decipher = AES.new(key, AES.MODE_CBC, iv)
decrypted_padded = decipher.decrypt(ciphertext)
decrypted = bytearray(unpad(decrypted_padded, AES.block_size))

state = [
    0x11223344,
    0xabacadae,
    0x1c0de1c0,
    0x13372025
]

state = transform(state, len(decrypted))
xored_1 = prng_xor_1(state, decrypted.copy())
for i in range(len(state)):
    decrypted_p2, rand = prng_xor_2(state[i], xored_1.copy())
    try:
        print(decrypted_p2.decode())
    except Exception:
        continue
