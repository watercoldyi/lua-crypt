#include <stdint.h>
#include <string.h>
#include "lua.h"
#include "lauxlib.h"

/*
 * SHA-256（FIPS 180-4）实现。
 * 对外接口：crypt.sha256(s) 返回 32 字节二进制摘要，与 crypt.sha1 一致。
 */

typedef struct {
	uint32_t state[8];
	uint64_t count; /* 已处理的字节数 */
	uint8_t buffer[64];
} SHA256_CTX;

static const uint32_t K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define BSIG1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SSIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SSIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static void
sha256_init(SHA256_CTX *ctx) {
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
	ctx->count = 0;
}

static void
sha256_transform(SHA256_CTX *ctx, const uint8_t block[64]) {
	uint32_t w[64];
	uint32_t a, b, c, d, e, f, g, h;
	uint32_t t1, t2;
	int i;

	/* 按大端序读入 16 个 32 位字 */
	for (i = 0; i < 16; ++i) {
		w[i] = (uint32_t)block[i * 4] << 24 |
		       (uint32_t)block[i * 4 + 1] << 16 |
		       (uint32_t)block[i * 4 + 2] << 8 |
		       (uint32_t)block[i * 4 + 3];
	}
	for (i = 16; i < 64; ++i) {
		w[i] = SSIG1(w[i - 2]) + w[i - 7] + SSIG0(w[i - 15]) + w[i - 16];
	}

	a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
	e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + BSIG1(e) + CH(e, f, g) + K[i] + w[i];
		t2 = BSIG0(a) + MAJ(a, b, c);
		h = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}

	ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
	ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void
sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len) {
	size_t index = (size_t)(ctx->count & 0x3f);
	size_t part = 64 - index;
	size_t i = 0;

	ctx->count += len;
	if (len >= part) {
		memcpy(ctx->buffer + index, data, part);
		sha256_transform(ctx, ctx->buffer);
		for (i = part; i + 64 <= len; i += 64) {
			sha256_transform(ctx, data + i);
		}
		index = 0;
	}
	memcpy(ctx->buffer + index, data + i, len - i);
}

static void
sha256_final(SHA256_CTX *ctx, uint8_t digest[32]) {
	uint64_t bits = ctx->count << 3;
	size_t index = (size_t)(ctx->count & 0x3f);
	uint8_t pad[64 + 8];
	uint8_t lenbuf[8];
	size_t padlen = (index < 56) ? (56 - index) : (120 - index);
	int i;

	memset(pad, 0, sizeof(pad));
	pad[0] = 0x80;
	sha256_update(ctx, pad, padlen);

	for (i = 0; i < 8; ++i) {
		lenbuf[i] = (uint8_t)(bits >> (56 - i * 8));
	}
	sha256_update(ctx, lenbuf, sizeof(lenbuf));

	for (i = 0; i < 8; ++i) {
		digest[i * 4] = (uint8_t)(ctx->state[i] >> 24);
		digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
		digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
		digest[i * 4 + 3] = (uint8_t)ctx->state[i];
	}
}

int
lsha256(lua_State *L) {
	size_t sz = 0;
	const uint8_t *s = (const uint8_t *)luaL_checklstring(L, 1, &sz);
	SHA256_CTX ctx;
	uint8_t digest[32];

	sha256_init(&ctx);
	sha256_update(&ctx, s, sz);
	sha256_final(&ctx, digest);
	lua_pushlstring(L, (const char *)digest, sizeof(digest));
	return 1;
}

/*
 * HMAC-SHA256（RFC 2104）：先按 64 字节块处理密钥，再做 ipad/opad 两层哈希。
 * 提供流式版本，方便 HKDF 分多段喂数据。
 */

typedef struct {
	SHA256_CTX inner;
	SHA256_CTX outer;
} HMAC_SHA256_CTX;

static void
hmac_sha256_init(HMAC_SHA256_CTX *ctx, const uint8_t *key, size_t keylen) {
	uint8_t k[64];
	size_t i;

	memset(k, 0, sizeof(k));
	if (keylen > sizeof(k)) {
		/* 密钥超过一个块时先哈希成 32 字节 */
		SHA256_CTX tmp;
		uint8_t digest[32];
		sha256_init(&tmp);
		sha256_update(&tmp, key, keylen);
		sha256_final(&tmp, digest);
		memcpy(k, digest, sizeof(digest));
	} else if (keylen > 0) {
		memcpy(k, key, keylen);
	}

	for (i = 0; i < sizeof(k); ++i) {
		k[i] ^= 0x36;
	}
	sha256_init(&ctx->inner);
	sha256_update(&ctx->inner, k, sizeof(k));

	for (i = 0; i < sizeof(k); ++i) {
		k[i] ^= 0x36 ^ 0x5c;
	}
	sha256_init(&ctx->outer);
	sha256_update(&ctx->outer, k, sizeof(k));
}

static void
hmac_sha256_update(HMAC_SHA256_CTX *ctx, const uint8_t *data, size_t len) {
	sha256_update(&ctx->inner, data, len);
}

static void
hmac_sha256_final(HMAC_SHA256_CTX *ctx, uint8_t out[32]) {
	uint8_t digest[32];
	sha256_final(&ctx->inner, digest);
	sha256_update(&ctx->outer, digest, sizeof(digest));
	sha256_final(&ctx->outer, out);
}

static void
hmac_sha256(const uint8_t *key, size_t keylen, const uint8_t *data, size_t len, uint8_t out[32]) {
	HMAC_SHA256_CTX ctx;
	hmac_sha256_init(&ctx, key, keylen);
	hmac_sha256_update(&ctx, data, len);
	hmac_sha256_final(&ctx, out);
}

/* crypt.hmac_sha256(key, data) -> 32 字节二进制 */
int
lhmac_sha256(lua_State *L) {
	size_t keylen = 0, len = 0;
	const uint8_t *key = (const uint8_t *)luaL_checklstring(L, 1, &keylen);
	const uint8_t *data = (const uint8_t *)luaL_checklstring(L, 2, &len);
	uint8_t out[32];

	hmac_sha256(key, keylen, data, len, out);
	lua_pushlstring(L, (const char *)out, sizeof(out));
	return 1;
}

/* HKDF 输出上限：255 个 32 字节块 */
#define HKDF_SHA256_MAX_OUT (255 * 32)

/*
 * crypt.hkdf_sha256(ikm, salt, info, outlen) -> outlen 字节二进制（RFC 5869）
 * salt / info 可以传 nil，等价于空串。
 */
int
lhkdf_sha256(lua_State *L) {
	size_t ikmlen = 0, saltlen = 0, infolen = 0;
	const uint8_t *ikm = (const uint8_t *)luaL_checklstring(L, 1, &ikmlen);
	const char *salt = luaL_optlstring(L, 2, "", &saltlen);
	const char *info = luaL_optlstring(L, 3, "", &infolen);
	lua_Integer outlen = luaL_checkinteger(L, 4);
	uint8_t prk[32], t[32];
	uint8_t *out;
	size_t done = 0;
	unsigned counter = 1;

	if (outlen < 0 || outlen > HKDF_SHA256_MAX_OUT) {
		return luaL_error(L, "Invalid HKDF output length %d, need 0..%d",
			(int)outlen, HKDF_SHA256_MAX_OUT);
	}

	/* extract：PRK = HMAC(salt, IKM) */
	hmac_sha256((const uint8_t *)salt, saltlen, ikm, ikmlen, prk);

	out = (uint8_t *)lua_newuserdata(L, outlen == 0 ? 1 : (size_t)outlen);

	/* expand：T(i) = HMAC(PRK, T(i-1) || info || i) */
	while (done < (size_t)outlen) {
		HMAC_SHA256_CTX ctx;
		size_t n;
		uint8_t c = (uint8_t)counter;

		hmac_sha256_init(&ctx, prk, sizeof(prk));
		if (counter > 1) {
			hmac_sha256_update(&ctx, t, sizeof(t));
		}
		if (infolen > 0) {
			hmac_sha256_update(&ctx, (const uint8_t *)info, infolen);
		}
		hmac_sha256_update(&ctx, &c, 1);
		hmac_sha256_final(&ctx, t);

		n = (size_t)outlen - done;
		if (n > sizeof(t)) {
			n = sizeof(t);
		}
		memcpy(out + done, t, n);
		done += n;
		++counter;
	}

	lua_pushlstring(L, (const char *)out, (size_t)outlen);
	return 1;
}
