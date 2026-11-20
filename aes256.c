/* 把 tiny-AES-c 编译成 AES-256 版本，并给公开符号加 aes256_ 前缀。 */
#define AES256 1

#define AES_ctx aes256_ctx
#define AES_init_ctx aes256_init_ctx
#define AES_init_ctx_iv aes256_init_ctx_iv
#define AES_ctx_set_iv aes256_ctx_set_iv
#define AES_ECB_encrypt aes256_ECB_encrypt
#define AES_ECB_decrypt aes256_ECB_decrypt
#define AES_CBC_encrypt_buffer aes256_CBC_encrypt_buffer
#define AES_CBC_decrypt_buffer aes256_CBC_decrypt_buffer
#define AES_CTR_xcrypt_buffer aes256_CTR_xcrypt_buffer

#include "aes.c"

/*
 * 编译期断言：这份配置必须确实是 AES-256 且 CBC/ECB/CTR 全开，
 * 以保证轮密钥数组大小为 240 字节，与 aes_variants.h 中的结构体一致。
 */
#if (AES_KEYLEN != 32)
#error "aes256.c 必须按 AES-256 编译"
#endif
#if !(defined(CBC) && CBC == 1) || !(defined(ECB) && ECB == 1) || !(defined(CTR) && CTR == 1)
#error "aes256.c 需要同时开启 CBC/ECB/CTR"
#endif
