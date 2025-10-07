#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint32_t uint;
typedef uint8_t byte;

void shuffle_state(uint *param_1,uint param_2) {
    uint uVar1;
    uint uVar2;
    uint uVar3;
    uint uVar4;
    uint uVar5;
    uint uVar6;
    uint uVar7;

    uVar2 = param_2 * -0x61c8864f;
    uVar5 = param_2 << 0x10 | param_2 >> 0x10;
    uVar3 = (param_2 ^ 0xf00dabcd) << 0xb ^ param_2 ^ 0xf00dabcd;
    uVar4 = (0x13371346 - param_2) * 0x800 ^ 0x13371346 - param_2;
    uVar1 = param_2 * -0x44327800 ^ uVar2;
    uVar2 = uVar3 >> 8 ^ uVar2 >> 0x13 ^ uVar2 ^ uVar3;
    uVar5 = uVar5 << 0xb ^ uVar5;
    uVar6 = uVar5 >> 8 ^ uVar5 ^ uVar2;
    uVar5 = uVar2 << 0xb ^ uVar2;
    uVar7 = uVar6 ^ uVar2 >> 0x13;
    uVar3 = uVar4 >> 8 ^ uVar4 ^ uVar7;
    uVar7 = uVar7 << 0xb ^ uVar7;
    uVar2 = uVar3 ^ uVar6 >> 0x13;
    uVar4 = uVar1 >> 8 ^ uVar1 ^ uVar2;
    uVar2 = uVar2 << 0xb ^ uVar2;
    uVar3 = uVar4 ^ uVar3 >> 0x13;
    uVar1 = uVar5 >> 8 ^ uVar5 ^ uVar3;
    uVar3 = uVar3 << 0xb ^ uVar3;
    uVar4 = uVar1 ^ uVar4 >> 0x13;
    uVar5 = uVar7 >> 8 ^ uVar7 ^ uVar4;
    uVar4 = uVar4 << 0xb ^ uVar4;
    uVar1 = uVar5 ^ uVar1 >> 0x13;
    uVar2 = uVar2 >> 8 ^ uVar2 ^ uVar1;
    uVar1 = uVar1 << 0xb ^ uVar1;
    uVar5 = uVar2 ^ uVar5 >> 0x13;
    uVar6 = uVar3 >> 8 ^ uVar3 ^ uVar5;
    uVar5 = uVar5 << 0xb ^ uVar5;
    uVar7 = uVar6 ^ uVar2 >> 0x13;
    uVar3 = uVar4 >> 8 ^ uVar4 ^ uVar7;
    uVar7 = uVar7 << 0xb ^ uVar7;
    uVar2 = uVar3 ^ uVar6 >> 0x13;
    uVar4 = uVar1 >> 8 ^ uVar1 ^ uVar2;
    uVar2 = uVar2 << 0xb ^ uVar2;
    uVar3 = uVar4 ^ uVar3 >> 0x13;
    uVar1 = uVar5 >> 8 ^ uVar5 ^ uVar3;
    uVar3 = uVar3 << 0xb ^ uVar3;
    uVar5 = uVar1 ^ uVar4 >> 0x13;
    uVar7 = uVar7 >> 8 ^ uVar7 ^ uVar5;
    uVar5 = uVar5 << 0xb ^ uVar5;
    uVar1 = uVar7 ^ uVar1 >> 0x13;
    uVar4 = uVar2 >> 8 ^ uVar2 ^ uVar1;
    uVar1 = uVar1 << 0xb ^ uVar1;
    uVar2 = uVar4 ^ uVar7 >> 0x13;
    uVar7 = uVar3 >> 8 ^ uVar3 ^ uVar2;
    uVar2 = uVar2 << 0xb ^ uVar2;
    uVar4 = uVar7 ^ uVar4 >> 0x13;
    uVar3 = uVar5 >> 8 ^ uVar5 ^ uVar4;
    uVar4 = uVar4 << 0xb ^ uVar4;
    uVar5 = uVar3 ^ uVar7 >> 0x13;
    uVar7 = uVar1 >> 8 ^ uVar1 ^ uVar5;
    uVar5 = uVar5 << 0xb ^ uVar5;
    uVar6 = uVar7 ^ uVar3 >> 0x13;
    uVar1 = uVar2 >> 8 ^ uVar2 ^ uVar6;
    uVar2 = uVar1 ^ uVar7 >> 0x13;
    uVar3 = uVar4 >> 8 ^ uVar4 ^ uVar2;
    uVar1 = uVar3 ^ uVar1 >> 0x13;
    param_1[3] = uVar5 >> 8 ^ uVar5 ^ uVar1 ^ uVar3 >> 0x13;
    *param_1 = uVar6;
    param_1[1] = uVar2;
    param_1[2] = uVar1;
    return;
}

void transform_flag(char* flag_ptr, uint len, uint key[4]) {
    uint uVar36;
    uint uVar40;
    uint rand;
    for (int i = 0; i < len; i++) {
      uVar36 = key[0] << 0xb ^ key[0];
      uVar36 = uVar36 >> 8 ^ key[3] >> 0x13 ^ uVar36 ^ key[3];
      uVar40 = (uVar36 >> 0x10 ^ uVar36) * 0x45d9f3b;
      rand = (uVar40 >> 0x10 ^ uVar40) * 0x3848f357;
      if (flag_ptr == 0x0) {
          //printf("0x%08X,", rand);
      }
      else {
          flag_ptr[i] = flag_ptr[i] ^ (byte)((uint)rand >> 0x10) ^ (byte)rand;
      }
      uVar40 = key[1] << 0xb ^ key[1];
      key[0] = key[2];
      uVar40 = uVar40 >> 8 ^ uVar40 ^ uVar36;
      key[1] = key[3];
      key[3] = uVar36 >> 0x13 ^ uVar40;
      uVar40 = (uVar40 >> 0x10 ^ key[3]) * 0x45d9f3b;
      uVar40 = (uVar40 >> 0x10 ^ uVar40) * 0x3848f357;
      key[2] = uVar36;
      shuffle_state(key, uVar40 & 0x7fffffff ^ uVar40 >> 0x10);
    }
}

struct crypto {
    uint8_t key[32];
    uint8_t IV[16];
};

uint32_t multipliers[] = {
    0x40a25379, 0x56b02995, 0x43ba1741, -0x173e01c3,
    0x67fbeea9, 0x7f6c1805, -0x7fd3f40f, 0x567ae02d,
    0xf56bad9, 0xc287375, -0xb6f465f, -0x3f8068e3,
    -0x560397f7, 0x45c82be5, -0x2200afaf, 0x284a930d,
    0x4fa110b9, 0xbb8f1d5, -0x2d6f417f, 0x366b087d,
    -0x54cd3817, -0x2cc373bb, 0x405baf31, -0x58f70993,
    0x3c78f019, 0x3aa6d3b5, 0x1b6698e1, -0x46f506a3,
    -0x3806c6b7, -0x78d947db, -0x241b546f, 0x2c97814d,
    0x41cfddf9, 0xb718a15, -0x5b680a3f, 0x50c262bd,
    0x4224b129, 0xc1bd085, -0x4f611d8f, -0x3663a353,
    0x35713559, 0x11e303f5, 0x23430821, 0x7cc2ab9d,
    -0x1b88e577, 0x45421465, -0x52c692f, 0x807bf8d,
};

uint32_t adds[] = {
    0x81195ce6U, 0x5039a011U, 0x3e314290U, 0x22f11713U,
    0x77948382U, 0x96dd9c3dU, 0xedc4fe0cU, 0x8476d49fU,
    0x2e15555eU, 0x20ad96a9, 0x7e1dbec8U, -0x572d7d95,
    0x1e278e7aU, 0xd2f65b55U, 0x98520c4U, 0xa2974c77U,
    0xfe1682f6U, 0x898e6de1U, 0x824e1920U, 0x8348d363U,
    0x852b5492U, 0xf0d1690dU, 0x8c0d79cU, 0xa5fd87efU,
    0x7c93616eU, 0xd497b279U, 0xe532ab58U, 0xc819fcbbU,
    0xe6ad658aU, 0x8bb51625U, 0xb9583054U, 0xd1f05dc7U,
    0x50689d06U, 0xafb45fb1U, 0xf98783b0U, 0x9d9ad3b3U,
    0x9aded9a2U, 0xee3f19ddU, 0x45df052cU, 0x7b6d3f3fU,
    0xb149e17eU, 0x30a87249U, 0x8363abe8U, 0xf35d3b0bU,
    0x489b709aU, 0xc20b34f5U, 0x52f513e4U, 0x5c3bf317U,
};

void generate_crypto(struct crypto *key_and_iv, uint32_t rand) {

    uint32_t temp[48];
    for (int i = 0; i < 48; i++) {
        uint32_t result = (rand * multipliers[i] + adds[i]) >> 0x10;
        temp[i] = (uint32_t)result & 0xff;
    }

    for (int i = 0; i < 4; i++) {
        int idx = i*4;
        int top = 16, bot = 0;
        int fill_idx = top - idx + bot;
        key_and_iv->key[fill_idx - 1] = (uint8_t)temp[idx+3] ^ 0x25;
        key_and_iv->key[fill_idx - 2] = (uint8_t)temp[idx+2] ^ 0x25;
        key_and_iv->key[fill_idx - 3] = (uint8_t)temp[idx+1] ^ 0x25;
        key_and_iv->key[fill_idx - 4] = (uint8_t)temp[idx+0] ^ 0x25;
    }

    for (int i = 4; i < 8; i++) {
        int idx = i*4;
        int top = 32, bot = 16;
        int fill_idx = top - idx + bot;
        key_and_iv->key[fill_idx - 1] = (uint8_t)temp[idx+3] ^ 0x25;
        key_and_iv->key[fill_idx - 2] = (uint8_t)temp[idx+2] ^ 0x25;
        key_and_iv->key[fill_idx - 3] = (uint8_t)temp[idx+1] ^ 0x25;
        key_and_iv->key[fill_idx - 4] = (uint8_t)temp[idx+0] ^ 0x25;
    }

    for (int i = 8; i < 12; i++) {
        int idx = i*4;
        int top = 48, bot = 32;
        int fill_idx = top - idx + bot;
        key_and_iv->key[fill_idx - 1] = (uint8_t)temp[idx + 3] ^ 0x37;
        key_and_iv->key[fill_idx - 2] = (uint8_t)temp[idx+2] ^ 0x37;
        key_and_iv->key[fill_idx - 3] = (uint8_t)temp[idx+1] ^ 0x37;
        key_and_iv->key[fill_idx - 4] = (uint8_t)temp[idx+0] ^ 0x37;
    }
}

int parse_hex_bytes(const char *hex, uint8_t *out, int expected_len) {
    int hexlen = (int)strlen(hex);
    if (hexlen != expected_len * 2) return -1;
    for (int i = 0; i < expected_len; ++i) {
        unsigned int v;
        if (sscanf(hex + 2*i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <16-byte-hex-key (32 hex chars)>\n", argv[0]);
        return 1;
    }

    uint8_t target_key[16];
    if (parse_hex_bytes(argv[1], target_key, 16) != 0) {
        fprintf(stderr, "Failed to parse hex key; ensure exactly 32 hex chars (16 bytes)\n");
        return 1;
    }

    struct crypto key_and_iv = {};
    for (int seed = 0; seed < 0xffffffff; seed ++) {
        generate_crypto(&key_and_iv, seed);
        if (memcmp(key_and_iv.IV, target_key, 16) == 0) {
            printf("rand=0x%08x, key=", seed);
            for (int i = 0; i < 32; i++) {
                printf("%02x", key_and_iv.key[i]);
            }
            printf("\n");
            break;
        }
    }
}
