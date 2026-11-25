#ifndef LUA_CRYPT_X25519_H
#define LUA_CRYPT_X25519_H

#include <stddef.h>
#include <stdint.h>

#define X25519_KEY_SIZE 32

/* 计算 RFC 7748 定义的 X25519，调用方负责拒绝全零共享秘密。 */
void lua_crypt_x25519(uint8_t out[X25519_KEY_SIZE],
    const uint8_t private_key[X25519_KEY_SIZE],
    const uint8_t public_key[X25519_KEY_SIZE]);

/* 清理临时秘密缓冲区，防止编译器省略写入。 */
void lua_crypt_wipe(void *secret, size_t size);

#endif
