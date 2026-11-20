#include <stdio.h>
#include "lua.h"
#include "lauxlib.h"
#include "md5.h"


/*
 * 函数式 reader：反复调用 fn()，每次返回一块数据，返回 nil 或空串表示结束。
 * 返回读取到的总字节数。
 */
static size_t
md5_fnreader(lua_State *L, MD5_CTX *ctx) {
	size_t total = 0;

	luaL_checkstack(L, 2, "md5 reader");
	for (;;) {
		size_t n = 0;
		const char *s;

		lua_pushvalue(L, 1);
		lua_call(L, 0, 1);

		if (lua_isnil(L, -1)) {
			lua_pop(L, 1);
			break;
		}
		if (!lua_isstring(L, -1)) {
			luaL_error(L, "reader function must return a string or nil");
		}
		s = lua_tolstring(L, -1, &n);
		if (n == 0) {
			/* 空串视为结束，避免 reader 无限返回空串 */
			lua_pop(L, 1);
			break;
		}
		MD5Update(ctx, (unsigned char *)s, n);
		total += n;
		lua_pop(L, 1);
	}
	return total;
}

/*
 * crypt.md5(s | fn)
 * s 为字符串时直接计算；s 为函数时反复调用它读取数据块，返回 nil 结束。
 * 零字节输入返回标准 MD5（与 md5file 和标准一致）。
 */
int
lmd5sumhex(lua_State *L) {
	MD5_CTX ctx;
	char hex[32];
	int t = lua_type(L, 1);

	if (t == LUA_TSTRING) {
		size_t n = 0;
		const char *s = lua_tolstring(L, 1, &n);
		MD5Init(&ctx);
		MD5Update(&ctx, (unsigned char *)s, n);
	} else if (t == LUA_TFUNCTION) {
		MD5Init(&ctx);
		md5_fnreader(L, &ctx);
	} else {
		return luaL_error(L, "argument #1 must be a string or a function");
	}

	MD5Final(&ctx);
	MD5Hex(&ctx, hex);
	lua_pushlstring(L, hex, 32);
	return 1;
}

// crypt.md5file(path)：计算文件的 md5，打开失败返回 nil
int
lmd5file(lua_State *L) {
	const char *path = luaL_checkstring(L, 1);
	FILE *f = fopen(path, "rb");
	if (f == NULL) {
		lua_pushnil(L);
		return 1;
	}
	char buf[4096];
	MD5_CTX ctx;
	MD5Init(&ctx);
	size_t n = 0;
	while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
		MD5Update(&ctx, (unsigned char *)buf, (unsigned int)n);
	}
	fclose(f);
	MD5Final(&ctx);
	char hex[32];
	MD5Hex(&ctx, hex);
	lua_pushlstring(L, hex, 32);
	return 1;
}
