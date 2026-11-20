#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "lua.h"
#include "lauxlib.h"
#include "aes_variants.h"

#define AES_BLOCKLEN 16

/* AES-128/256 的上下文合并成一个联合体，按 key 长度选择 */
union aes_ctx_any {
	struct aes128_ctx c128;
	struct aes256_ctx c256;
};

/* 根据 key 长度返回 128/256，非法长度返回 0 */
static int
aes_bits(size_t keylen) {
	switch (keylen) {
	case 16: return 128;
	case 32: return 256;
	default: return 0;
	}
}

static void
aes_init(union aes_ctx_any *ctx, int bits, const uint8_t *key) {
	switch (bits) {
	case 128: aes128_init_ctx(&ctx->c128, key); break;
	default:  aes256_init_ctx(&ctx->c256, key); break;
	}
}

static void
aes_init_iv(union aes_ctx_any *ctx, int bits, const uint8_t *key, const uint8_t *iv) {
	switch (bits) {
	case 128: aes128_init_ctx_iv(&ctx->c128, key, iv); break;
	default:  aes256_init_ctx_iv(&ctx->c256, key, iv); break;
	}
}

static void
aes_ecb(union aes_ctx_any *ctx, int bits, uint8_t *buf, size_t len, int decrypt) {
	size_t i;
	for (i = 0; i < len; i += AES_BLOCKLEN) {
		switch (bits) {
		case 128:
			if (decrypt) aes128_ECB_decrypt(&ctx->c128, buf + i);
			else aes128_ECB_encrypt(&ctx->c128, buf + i);
			break;
		default:
			if (decrypt) aes256_ECB_decrypt(&ctx->c256, buf + i);
			else aes256_ECB_encrypt(&ctx->c256, buf + i);
			break;
		}
	}
}

static void
aes_cbc(union aes_ctx_any *ctx, int bits, uint8_t *buf, size_t len, int decrypt) {
	switch (bits) {
	case 128:
		if (decrypt) aes128_CBC_decrypt_buffer(&ctx->c128, buf, len);
		else aes128_CBC_encrypt_buffer(&ctx->c128, buf, len);
		break;
	default:
		if (decrypt) aes256_CBC_decrypt_buffer(&ctx->c256, buf, len);
		else aes256_CBC_encrypt_buffer(&ctx->c256, buf, len);
		break;
	}
}

static void
aes_ctr(union aes_ctx_any *ctx, int bits, uint8_t *buf, size_t len) {
	switch (bits) {
	case 128: aes128_CTR_xcrypt_buffer(&ctx->c128, buf, len); break;
	default:  aes256_CTR_xcrypt_buffer(&ctx->c256, buf, len); break;
	}
}

/* 标准 PKCS7 填充：总是补 1..16 字节，整块输入也补满一整块 */
static size_t
pkcs7_pad(uint8_t *buf, size_t len) {
	size_t pad = AES_BLOCKLEN - (len % AES_BLOCKLEN);
	memset(buf + len, (int)pad, pad);
	return len + pad;
}

/* 去除 PKCS7 填充，成功返回 1 并写出明文长度（可能为 0），非法返回 0 */
static int
pkcs7_unpad(uint8_t *buf, size_t len, size_t *out) {
	unsigned char pv;
	unsigned int diff = 0;
	size_t i;

	if (len == 0 || len % AES_BLOCKLEN != 0) return 0;
	pv = buf[len - 1];
	/* 填充长度必须在 1..16；len 至少 16，所以无需再判断 pv > len */
	if (pv == 0 || pv > AES_BLOCKLEN) return 0;

	/* 用掩码比较最后 pv 个字节，避免提前返回泄露填充内容 */
	for (i = 0; i < AES_BLOCKLEN; ++i) {
		unsigned char mask = (unsigned char)-(size_t)(i < pv);
		diff |= (buf[len - 1 - i] ^ pv) & mask;
	}
	if (diff != 0) return 0;

	*out = len - pv;
	return 1;
}

/*
 * crypt.aesencode(key, iv, data [, mode])
 * crypt.aesdecode(key, iv, data [, mode])
 *
 * key  : 16 / 32 字节，对应 AES-128 / 256
 * iv   : 16 字节；ecb 模式忽略（可传 nil）
 * mode : "cbc"（默认，带 PKCS7 填充）/"ecb"（无填充，长度须为 16 的倍数）
 *        /"ctr"（无填充，加解密同一个操作）
 */
static int
aes_crypt(lua_State *L, int decrypt) {
	size_t keylen = 0, len = 0;
	const uint8_t *key = (const uint8_t *)luaL_checklstring(L, 1, &keylen);
	const char *mode = luaL_optstring(L, 4, "cbc");
	const uint8_t *data;
	const uint8_t *iv = NULL;
	union aes_ctx_any ctx;
	uint8_t *buf;
	size_t outlen;
	int bits, is_cbc, is_ecb, is_ctr;

	bits = aes_bits(keylen);
	if (bits == 0) {
		return luaL_error(L, "Invalid AES key size %d, need 16 or 32 bytes", (int)keylen);
	}

	is_cbc = strcmp(mode, "cbc") == 0;
	is_ecb = strcmp(mode, "ecb") == 0;
	is_ctr = strcmp(mode, "ctr") == 0;
	if (!is_cbc && !is_ecb && !is_ctr) {
		return luaL_error(L, "Invalid AES mode '%s', need cbc, ecb or ctr", mode);
	}

	data = (const uint8_t *)luaL_checklstring(L, 3, &len);

	if (!is_ecb) {
		size_t ivlen = 0;
		iv = (const uint8_t *)luaL_checklstring(L, 2, &ivlen);
		if (ivlen != AES_BLOCKLEN) {
			return luaL_error(L, "Invalid IV size %d, need 16 bytes", (int)ivlen);
		}
	}

	if (is_ecb && (len == 0 || len % AES_BLOCKLEN != 0)) {
		return luaL_error(L, "Invalid AES-ECB data size %d, need positive multiple of 16", (int)len);
	}
	if (is_cbc && decrypt && (len == 0 || len % AES_BLOCKLEN != 0)) {
		return luaL_error(L, "Invalid AES-CBC cipher text size %d, need positive multiple of 16", (int)len);
	}

	/* CBC 加密最多在末尾补一整块，CTR/ECB 不填充 */
	outlen = len;
	if (is_cbc && !decrypt) {
		outlen = len + AES_BLOCKLEN;
	}

	buf = (uint8_t *)lua_newuserdata(L, outlen == 0 ? 1 : outlen);
	memcpy(buf, data, len);
	if (is_cbc && !decrypt) {
		outlen = pkcs7_pad(buf, len);
	}

	if (is_ecb) {
		aes_init(&ctx, bits, key);
		aes_ecb(&ctx, bits, buf, outlen, decrypt);
	} else {
		aes_init_iv(&ctx, bits, key, iv);
		if (is_ctr) {
			aes_ctr(&ctx, bits, buf, outlen);
		} else {
			aes_cbc(&ctx, bits, buf, outlen, decrypt);
		}
	}

	if (is_cbc && decrypt) {
		size_t plainlen = 0;
		if (!pkcs7_unpad(buf, outlen, &plainlen)) {
			lua_pushnil(L);
			lua_pushliteral(L, "invalid padding");
			return 2;
		}
		lua_pushlstring(L, (const char *)buf, plainlen);
		return 1;
	}

	lua_pushlstring(L, (const char *)buf, outlen);
	return 1;
}

int
laesencode(lua_State *L) {
	return aes_crypt(L, 0);
}

int
laesdecode(lua_State *L) {
	return aes_crypt(L, 1);
}
