#include <lua.h>
#include <lauxlib.h>

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#elif defined(__linux__)
#include <sys/types.h>
#include <sys/random.h>
#include <errno.h>
#endif

/* macOS / BSD 直接用 arc4random_buf */
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#define HAVE_ARC4RANDOM 1
#endif

#define SMALL_CHUNK 256

#if !defined(_WIN32) && !defined(HAVE_ARC4RANDOM)
/* 其他 POSIX 平台的兜底：读 /dev/urandom */
static int
urandom_fill(uint8_t *buf, size_t len) {
	FILE *f = fopen("/dev/urandom", "rb");
	size_t n;
	if (f == NULL) {
		return -1;
	}
	n = fread(buf, 1, len, f);
	fclose(f);
	return n == len ? 0 : -1;
}
#endif

/* 用操作系统的 CSPRNG 填充 buf，成功返回 0，失败返回 -1 */
static int
secure_random(uint8_t *buf, size_t len) {
#if defined(_WIN32)
	if (BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
		return -1;
	}
	return 0;
#elif defined(HAVE_ARC4RANDOM)
	arc4random_buf(buf, len);
	return 0;
#elif defined(__linux__)
	size_t off = 0;
	while (off < len) {
		ssize_t n = getrandom(buf + off, len - off, 0);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			break; /* 内核不支持 getrandom 时回退到 /dev/urandom */
		}
		if (n == 0) {
			break;
		}
		off += (size_t)n;
	}
	if (off == len) {
		return 0;
	}
	return urandom_fill(buf, len);
#else
	return urandom_fill(buf, len);
#endif
}

static int
lrandomkey(lua_State *L) {
	uint8_t tmp[8];
	if (secure_random(tmp, sizeof(tmp)) != 0) {
		return luaL_error(L, "failed to get random bytes from system CSPRNG");
	}
	lua_pushlstring(L, (const char *)tmp, 8);
	return 1;
}

static int
ltohex(lua_State *L) {
	static char hex[] = "0123456789abcdef";
	size_t sz = 0;
	const uint8_t * text = (const uint8_t *)luaL_checklstring(L, 1, &sz);
	char tmp[SMALL_CHUNK];
	char *buffer = tmp;
	if (sz > SMALL_CHUNK/2) {
		buffer = lua_newuserdata(L, sz * 2);
	}
	int i;
	for (i=0;i<sz;i++) {
		buffer[i*2] = hex[text[i] >> 4];
		buffer[i*2+1] = hex[text[i] & 0xf];
	}
	lua_pushlstring(L, buffer, sz * 2);
	return 1;
}

#define HEX(v,c) { char tmp = (char) c; if (tmp >= '0' && tmp <= '9') { v = tmp-'0'; } else { v = tmp - 'a' + 10; } }

static int
lfromhex(lua_State *L) {
	size_t sz = 0;
	const char * text = luaL_checklstring(L, 1, &sz);
	if (sz % 2) {
		return luaL_error(L, "Invalid hex text size %d", (int)sz);
	}
	char tmp[SMALL_CHUNK];
	char *buffer = tmp;
	if (sz > SMALL_CHUNK*2) {
		buffer = lua_newuserdata(L, sz / 2);
	}
	int i;
	for (i=0;i<sz;i+=2) {
		uint8_t hi,low;
		HEX(hi, text[i]);
		HEX(low, text[i+1]);
		if (hi > 16 || low > 16) {
			return luaL_error(L, "Invalid hex text", text);
		}
		buffer[i/2] = hi<<4 | low;
	}
	lua_pushlstring(L, buffer, i/2);
	return 1;
}

// powmodp64 for DH-key exchange

// The biggest 64bit prime
#define P 0xffffffffffffffc5ull

static inline uint64_t
mul_mod_p(uint64_t a, uint64_t b) {
	uint64_t m = 0;
	while(b) {
		if(b&1) {
			uint64_t t = P-a;
			if ( m >= t) {
				m -= t;
			} else {
				m += a;
			}
		}
		if (a >= P - a) {
			a = a * 2 - P;
		} else {
			a = a * 2;
		}
		b>>=1;
	}
	return m;
}

static inline uint64_t
pow_mod_p(uint64_t a, uint64_t b) {
	if (b==1) {
		return a;
	}
	uint64_t t = pow_mod_p(a, b>>1);
	t = mul_mod_p(t,t);
	if (b % 2) {
		t = mul_mod_p(t, a);
	}
	return t;
}

// calc a^b % p
static uint64_t
powmodp(uint64_t a, uint64_t b) {
	if (a > P)
		a%=P;
	return pow_mod_p(a,b);
}

static void
push64(lua_State *L, uint64_t r) {
	uint8_t tmp[8];
	tmp[0] = r & 0xff;
	tmp[1] = (r >> 8 )& 0xff;
	tmp[2] = (r >> 16 )& 0xff;
	tmp[3] = (r >> 24 )& 0xff;
	tmp[4] = (r >> 32 )& 0xff;
	tmp[5] = (r >> 40 )& 0xff;
	tmp[6] = (r >> 48 )& 0xff;
	tmp[7] = (r >> 56 )& 0xff;

	lua_pushlstring(L, (const char *)tmp, 8);
}

/* 读取两个 8 字节参数，按小端拼成两个 64 位整数 */
static void
read64(lua_State *L, uint32_t xx[2], uint32_t yy[2]) {
	size_t sz = 0;
	const uint8_t *x = (const uint8_t *)luaL_checklstring(L, 1, &sz);
	if (sz != 8) {
		luaL_error(L, "Invalid DH argument #1, need 8 bytes");
	}
	const uint8_t *y = (const uint8_t *)luaL_checklstring(L, 2, &sz);
	if (sz != 8) {
		luaL_error(L, "Invalid DH argument #2, need 8 bytes");
	}
	xx[0] = x[0] | x[1]<<8 | x[2]<<16 | x[3]<<24;
	xx[1] = x[4] | x[5]<<8 | x[6]<<16 | x[7]<<24;
	yy[0] = y[0] | y[1]<<8 | y[2]<<16 | y[3]<<24;
	yy[1] = y[4] | y[5]<<8 | y[6]<<16 | y[7]<<24;
}

static int
ldhsecret(lua_State *L) {
	uint32_t x[2], y[2];
	read64(L, x, y);
	uint64_t r = powmodp((uint64_t)x[0] | (uint64_t)x[1]<<32,
		(uint64_t)y[0] | (uint64_t)y[1]<<32);

	push64(L, r);

	return 1;
}

#define G 5

static int
ldhexchange(lua_State *L) {
	size_t sz = 0;
	const uint8_t *x = (const uint8_t *)luaL_checklstring(L, 1, &sz);
	if (sz != 8) {
		luaL_error(L, "Invalid hmac x");
	}
	uint32_t xx[2];
	xx[0] = x[0] | x[1]<<8 | x[2]<<16 | x[3]<<24;
	xx[1] = x[4] | x[5]<<8 | x[6]<<16 | x[7]<<24;

	uint64_t r = powmodp(5,	(uint64_t)xx[0] | (uint64_t)xx[1]<<32);
	push64(L, r);
	return 1;
}

// base64

static int
lb64encode(lua_State *L) {
	static const char* encoding = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t sz = 0;
	const uint8_t * text = (const uint8_t *)luaL_checklstring(L, 1, &sz);
	int encode_sz = (sz + 2)/3*4;
	char tmp[SMALL_CHUNK];
	char *buffer = tmp;
	if (encode_sz > SMALL_CHUNK) {
		buffer = lua_newuserdata(L, encode_sz);
	}
	int i,j;
	j=0;
	for (i=0;i<(int)sz-2;i+=3) {
		uint32_t v = text[i] << 16 | text[i+1] << 8 | text[i+2];
		buffer[j] = encoding[v >> 18];
		buffer[j+1] = encoding[(v >> 12) & 0x3f];
		buffer[j+2] = encoding[(v >> 6) & 0x3f];
		buffer[j+3] = encoding[(v) & 0x3f];
		j+=4;
	}
	int padding = sz-i;
	uint32_t v;
	switch(padding) {
	case 1 :
		v = text[i];
		buffer[j] = encoding[v >> 2];
		buffer[j+1] = encoding[(v & 3) << 4];
		buffer[j+2] = '=';
		buffer[j+3] = '=';
		break;
	case 2 :
		v = text[i] << 8 | text[i+1];
		buffer[j] = encoding[v >> 10];
		buffer[j+1] = encoding[(v >> 4) & 0x3f];
		buffer[j+2] = encoding[(v & 0xf) << 2];
		buffer[j+3] = '=';
		break;
	}
	lua_pushlstring(L, buffer, encode_sz);
	return 1;
}

static inline int
b64index(uint8_t c) {
	static const int decoding[] = {62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,-1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51};
	int decoding_size = sizeof(decoding)/sizeof(decoding[0]);
	if (c<43) {
		return -1;
	}
	c -= 43;
	if (c>=decoding_size)
		return -1;
	return decoding[c];
}

static int
lb64decode(lua_State *L) {
	size_t sz = 0;
	const uint8_t * text = (const uint8_t *)luaL_checklstring(L, 1, &sz);
	int decode_sz = (sz+3)/4*3;
	char tmp[SMALL_CHUNK];
	char *buffer = tmp;
	if (decode_sz > SMALL_CHUNK) {
		buffer = lua_newuserdata(L, decode_sz);
	}
	int i,j;
	int output = 0;
	for (i=0;i<sz;) {
		int padding = 0;
		int c[4];
		for (j=0;j<4;) {
			if (i>=sz) {
				return luaL_error(L, "Invalid base64 text");
			}
			c[j] = b64index(text[i]);
			if (c[j] == -1) {
				++i;
				continue;
			}
			if (c[j] == -2) {
				++padding;
			}
			++i;
			++j;
		}
		uint32_t v;
		switch (padding) {
		case 0:
			v = (unsigned)c[0] << 18 | c[1] << 12 | c[2] << 6 | c[3];
			buffer[output] = v >> 16;
			buffer[output+1] = (v >> 8) & 0xff;
			buffer[output+2] = v & 0xff;
			output += 3;
			break;
		case 1:
			if (c[3] != -2 || (c[2] & 3)!=0) {
				return luaL_error(L, "Invalid base64 text");
			}
			v = (unsigned)c[0] << 10 | c[1] << 4 | c[2] >> 2 ;
			buffer[output] = v >> 8;
			buffer[output+1] = v & 0xff;
			output += 2;
			break;
		case 2:
			if (c[3] != -2 || c[2] != -2 || (c[1] & 0xf) !=0)  {
				return luaL_error(L, "Invalid base64 text");
			}
			v = (unsigned)c[0] << 2 | c[1] >> 4;
			buffer[output] = v;
			++ output;
			break;
		default:
			return luaL_error(L, "Invalid base64 text");
		}
	}
	lua_pushlstring(L, buffer, output);
	return 1;
}

int lhmac_sha1(lua_State *L);
int lsha1(lua_State *L);
int lsha256(lua_State *L);
int lmd5sumhex(lua_State *L);
int lmd5file(lua_State *L);
int laesencode(lua_State *L);
int laesdecode(lua_State *L);

int
luaopen_crypt(lua_State *L) {
	// luaL_checkversion 是 Lua 5.2 才引入的 API，LuaJIT 的 ABI 停留在 5.1，没有这个函数
#if LUA_VERSION_NUM >= 502
	luaL_checkversion(L);
#endif
	luaL_Reg l[] = {
		{ "randomkey", lrandomkey },
		{ "hexencode", ltohex },
		{ "hexdecode", lfromhex },
		{ "dhexchange", ldhexchange },
		{ "dhsecret", ldhsecret },
		{ "base64encode", lb64encode },
		{ "base64decode", lb64decode },
		{ "sha1", lsha1},
		{ "sha256", lsha256},
		{ "hmac_sha1", lhmac_sha1},
		{ "md5", lmd5sumhex },
		{ "md5file", lmd5file },
		{ "aesencode", laesencode },
		{ "aesdecode", laesdecode },
		{ NULL, NULL },
	};
	luaL_newlib(L,l);
	return 1;
}
