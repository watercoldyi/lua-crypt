#ifndef AES_VARIANTS_H
#define AES_VARIANTS_H

#include <stdint.h>
#include <stddef.h>

/*
 * tiny-AES-c 的密钥长度是编译期常量，为了在同一进程里同时支持
 * AES-128 和 AES-256，aes128.c / aes256.c 各包含一次 aes.c，
 * 并把公开符号加上对应前缀。AES-192 现实中使用极少，不再支持。
 *
 * 下面的结构体布局必须与 aes.c 里的 struct AES_ctx 完全一致：
 *   RoundKey[AES_keyExpSize] + Iv[16]
 * 对应 176 / 240 字节的轮密钥，再加 16 字节 IV。
 * aes128.c / aes256.c 末尾的编译期断言会确保实际配置与这里一致。
 */

struct aes128_ctx { uint8_t RoundKey[176]; uint8_t Iv[16]; };
struct aes256_ctx { uint8_t RoundKey[240]; uint8_t Iv[16]; };

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct aes128_ctx) == 176 + 16, "aes128_ctx 布局不匹配");
_Static_assert(sizeof(struct aes256_ctx) == 240 + 16, "aes256_ctx 布局不匹配");
#endif

#define AES_VARIANT_DECL(bits) \
	void aes##bits##_init_ctx(struct aes##bits##_ctx *ctx, const uint8_t *key); \
	void aes##bits##_init_ctx_iv(struct aes##bits##_ctx *ctx, const uint8_t *key, const uint8_t *iv); \
	void aes##bits##_ctx_set_iv(struct aes##bits##_ctx *ctx, const uint8_t *iv); \
	void aes##bits##_ECB_encrypt(const struct aes##bits##_ctx *ctx, uint8_t *buf); \
	void aes##bits##_ECB_decrypt(const struct aes##bits##_ctx *ctx, uint8_t *buf); \
	void aes##bits##_CBC_encrypt_buffer(struct aes##bits##_ctx *ctx, uint8_t *buf, size_t length); \
	void aes##bits##_CBC_decrypt_buffer(struct aes##bits##_ctx *ctx, uint8_t *buf, size_t length); \
	void aes##bits##_CTR_xcrypt_buffer(struct aes##bits##_ctx *ctx, uint8_t *buf, size_t length);

AES_VARIANT_DECL(128)
AES_VARIANT_DECL(256)

#undef AES_VARIANT_DECL

#endif // AES_VARIANTS_H
