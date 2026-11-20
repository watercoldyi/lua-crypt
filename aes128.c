/* 把 tiny-AES-c 编译成 AES-128 版本，并给公开符号加 aes128_ 前缀，
 * 避免与 AES-256 版本重名。核心代码不做任何修改。 */
#define AES_ctx aes128_ctx
#define AES_init_ctx aes128_init_ctx
#define AES_init_ctx_iv aes128_init_ctx_iv
#define AES_ctx_set_iv aes128_ctx_set_iv
#define AES_ECB_encrypt aes128_ECB_encrypt
#define AES_ECB_decrypt aes128_ECB_decrypt
#define AES_CBC_encrypt_buffer aes128_CBC_encrypt_buffer
#define AES_CBC_decrypt_buffer aes128_CBC_decrypt_buffer
#define AES_CTR_xcrypt_buffer aes128_CTR_xcrypt_buffer

#include "aes.c"

/*
 * 编译期断言：这份配置必须确实是 AES-128 且 CBC/ECB/CTR 全开。
 * 否则结构体布局会与 aes_variants.h 不一致（aes.c 会静默按 192/256 编译），
 * 后果是 laes.c 按错误尺寸分配上下文，造成越界读写。
 */
#if (AES_KEYLEN != 16)
#error "aes128.c 必须按 AES-128 编译，不要定义 AES192/AES256"
#endif
#if !(defined(CBC) && CBC == 1) || !(defined(ECB) && ECB == 1) || !(defined(CTR) && CTR == 1)
#error "aes128.c 需要同时开启 CBC/ECB/CTR"
#endif
