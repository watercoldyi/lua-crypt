local crypt = require "crypt"

-- base64
-- http://en.wikipedia.org/wiki/Base64

local base64_string = "any carnal pleasure."

for i = 20, 15, -1 do
	local s = string.sub(base64_string,1,i)
	print(string.format("Input ends with : %s \tOutput ends with: %s \tInput has %d bytes, output hash %d bytes.",
		s, crypt.base64encode(s), #s, #crypt.base64encode(s)))

	assert(s == crypt.base64decode(crypt.base64encode(s)))
end

-- RFC 7748 §6.1：验证双方公钥及共享秘密
do
	local alice_private = crypt.hexdecode "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	local bob_private = crypt.hexdecode "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
	local alice_public = crypt.dhexchange(alice_private)
	local bob_public = crypt.dhexchange(bob_private)
	assert(crypt.hexencode(alice_public) == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	assert(crypt.hexencode(bob_public) == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	local expected = crypt.hexdecode "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
	assert(crypt.dhsecret(bob_public, alice_private) == expected)
	assert(crypt.dhsecret(alice_public, bob_private) == expected)

	-- RFC 7748 要求忽略对端公钥的最高位。
	local high_bit = bob_public:sub(1, 31) .. string.char(bob_public:byte(32) + 128)
	assert(crypt.dhsecret(high_bit, alice_private) == expected)

	-- 非规范编码 p+9 应按模 p 解释，与基点 9 等价。
	local base_point_alias = crypt.hexdecode("f6" .. string.rep("ff", 30) .. "7f")
	assert(crypt.dhsecret(base_point_alias, alice_private) == alice_public)

	-- 长度正确的低阶点也必须因共享秘密全零而被拒绝。
	assert(not pcall(crypt.dhsecret, string.rep("\0", 32), alice_private))
	assert(not pcall(crypt.dhsecret, "\1" .. string.rep("\0", 31), alice_private))
	for _, len in ipairs { 0, 8, 31, 33 } do
		local wrong_length = string.rep("x", len)
		assert(not pcall(crypt.dhexchange, wrong_length))
		assert(not pcall(crypt.dhsecret, wrong_length, alice_private))
		assert(not pcall(crypt.dhsecret, bob_public, wrong_length))
	end
	assert(not pcall(crypt.dhexchange, 42))
end

-- 使用系统随机源生成双方私钥，并验证一次完整握手。
do
	local a, b = crypt.randomkey(), crypt.randomkey()
	local shared = crypt.dhsecret(crypt.dhexchange(b), a)
	assert(#shared == 32 and shared == crypt.dhsecret(crypt.dhexchange(a), b))
end

-- randomkey 使用系统 CSPRNG：长度为 32，多次调用不应重复。
local seen = {}
for _ = 1, 32 do
	local k = crypt.randomkey()
	assert(#k == 32)
	seen[k] = true
end
local n = 0
for _ in pairs(seen) do n = n + 1 end
assert(n == 32)

-- DES 及相关接口已移除
assert(crypt.hashkey == nil and crypt.desencode == nil and crypt.desdecode == nil and crypt.hmac64 == nil)

-- MD5

local md5_hello = "5EB63BBBE01EEED093CB22BB8F5ACDC3" -- 大写十六进制

assert(crypt.md5 "hello world" == md5_hello)
print("md5(hello world) = ", crypt.md5 "hello world")

-- 零字节输入返回标准 MD5（与 md5file、标准一致）
local md5_empty = "D41D8CD98F00B204E9800998ECF8427E"
assert(crypt.md5 "" == md5_empty)

-- 文件接口
local tmppath = os.tmpname()
local tf = assert(io.open(tmppath, "wb"))
tf:write "hello world"
tf:close()
assert(crypt.md5file(tmppath) == md5_hello)

-- 函数式 reader：每次返回一块数据，nil 结束
local pos = 1
local function reader()
	local s = ("hello world"):sub(pos, pos + 3)
	if #s == 0 then return nil end
	pos = pos + #s
	return s
end
assert(crypt.md5(reader) == md5_hello)

-- 没有任何数据时同样返回标准 MD5
assert(crypt.md5(function() return nil end) == md5_empty)

-- 参数只接受 string 或 function
assert(not pcall(crypt.md5, {}))
assert(not pcall(crypt.md5, 42))
-- reader 返回值非法时报错
assert(not pcall(crypt.md5, function() return {} end))

os.remove(tmppath)

-- SHA-256（FIPS 180-4 测试向量）
assert(crypt.hexencode(crypt.sha256 "") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
assert(crypt.hexencode(crypt.sha256 "abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
assert(crypt.hexencode(crypt.sha256 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
	"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
assert(crypt.hexencode(crypt.sha256(string.rep("a", 1000000))) ==
	"cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")

-- AES

local function hex2bin(s) return crypt.hexdecode(s) end
local function bin2hex(s) return crypt.hexencode(s) end

-- FIPS-197 单块 ECB 向量（AES-128 / AES-256）
local fips_block = hex2bin "00112233445566778899aabbccddeeff"
local fips = {
	{ key = "000102030405060708090a0b0c0d0e0f", ct = "69c4e0d86a7b0430d8cdb78070b4c55a" },
	{ key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", ct = "8ea2b7ca516745bfeafc49904b496089" },
}
for _, v in ipairs(fips) do
	local key = hex2bin(v.key)
	local ct = crypt.aesencode(key, nil, fips_block, "ecb")
	assert(bin2hex(ct) == v.ct)
	assert(crypt.aesdecode(key, nil, ct, "ecb") == fips_block)
end

-- NIST SP 800-38A AES-128 CBC / CTR 向量
local sp_key = hex2bin "2b7e151628aed2a6abf7158809cf4f3c"
local sp_iv_cbc = hex2bin "000102030405060708090a0b0c0d0e0f"
local sp_iv_ctr = hex2bin "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
local sp_pt = hex2bin "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
local sp_ct_cbc = "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7"
local sp_ct_ctr = "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee"

-- CBC 默认带 PKCS7，末尾会多一整块；前 64 字节应与标准向量一致
local cbc_out = crypt.aesencode(sp_key, sp_iv_cbc, sp_pt)
assert(#cbc_out == #sp_pt + 16)
assert(bin2hex(cbc_out):sub(1, 128) == sp_ct_cbc)
assert(crypt.aesdecode(sp_key, sp_iv_cbc, cbc_out) == sp_pt)

-- CTR 不填充，长度保持不变，加解密是同一个操作
local ctr_out = crypt.aesencode(sp_key, sp_iv_ctr, sp_pt, "ctr")
assert(bin2hex(ctr_out) == sp_ct_ctr)
assert(crypt.aesencode(sp_key, sp_iv_ctr, ctr_out, "ctr") == sp_pt)

-- PKCS7 填充长度与往返（0 字节也要补满一整块）
for _, n in ipairs { 0, 1, 15, 16, 17, 31, 32, 33, 100 } do
	local s = string.rep("x", n)
	local ct = crypt.aesencode(sp_key, sp_iv_cbc, s)
	assert(#ct == (math.floor(n / 16) + 1) * 16, "padding size mismatch at " .. n)
	assert(crypt.aesdecode(sp_key, sp_iv_cbc, ct) == s)
end

-- 两种密钥长度的 CBC 往返
for _, klen in ipairs { 16, 32 } do
	local key = string.rep("k", klen)
	local ct = crypt.aesencode(key, sp_iv_cbc, "hello aes")
	assert(crypt.aesdecode(key, sp_iv_cbc, ct) == "hello aes")
end

-- AES-192 已移除，24 字节密钥必须报错
assert(not pcall(crypt.aesencode, string.rep("k", 24), sp_iv_cbc, "x"))

-- 非法填充必须返回 nil + 错误信息，而不是崩溃或静默通过
local badblock = string.rep("A", 15) .. "\0" -- 末字节 0x00 不是合法填充
local badct = crypt.aesencode(sp_key, nil, badblock, "ecb")
local plain, err = crypt.aesdecode(sp_key, sp_iv_cbc, badct)
assert(plain == nil and type(err) == "string")

-- 参数校验
assert(not pcall(crypt.aesencode, "short", sp_iv_cbc, "x"))
assert(not pcall(crypt.aesencode, sp_key, "short", "x"))
assert(not pcall(crypt.aesencode, sp_key, sp_iv_cbc, "x", "nope"))
assert(not pcall(crypt.aesencode, sp_key, nil, "abc", "ecb"))
assert(not pcall(crypt.aesdecode, sp_key, sp_iv_cbc, "abc"))

print("aes tests passed")

