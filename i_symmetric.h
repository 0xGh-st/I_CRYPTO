#ifndef __I_SYMMETRIC_H__
#define __I_SYMMETRIC_H__
#include "edge_crypto.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#endif
#define I_EXPORT __attribute__ ((visibility("default")))
#define I_LOCAL  __attribute__ ((visibility("hidden")))


//test code
I_EXPORT const char* crypto_getStatusString(int p_status);
I_EXPORT void hexdump(const char* title, void* mem, unsigned int len);
I_EXPORT void printf_red(const char* const Format, ...);
I_EXPORT void print_result(const char* p_function, int p_result);

typedef struct I_CIPHER_CTX I_CIPHER_CTX;
/////////////////////////////////////header of function///////////////////////////////////////////////////
//keyword 'i' is ybkim's signature
I_EXPORT int i_enc(int p_cipherId,
	uint8_t* p_key, uint32_t p_keyLen,
	EDGE_CIPHER_PARAMETERS* p_param,
	uint8_t* p_input, uint32_t p_inputLen,
	uint8_t* p_output, uint32_t* p_outputLen);

I_EXPORT int i_dec(int p_cipherId,
	uint8_t* p_key, uint32_t p_keyLen,
	EDGE_CIPHER_PARAMETERS* p_param,
	uint8_t* p_input, uint32_t p_inputLen,
	uint8_t* p_output, uint32_t* p_outputLen);

I_EXPORT I_CIPHER_CTX* i_ctx_new();
I_EXPORT void i_ctx_reset(I_CIPHER_CTX* p_context);
I_EXPORT void i_ctx_free(I_CIPHER_CTX* p_context);
I_EXPORT int i_enc_init(I_CIPHER_CTX* p_context, const int p_cipher_id, uint8_t* p_key, uint32_t p_keylength, const EDGE_CIPHER_PARAMETERS* p_param);
I_EXPORT int i_enc_update(I_CIPHER_CTX* p_context, uint8_t* p_input, uint32_t p_inputlength, uint8_t* p_output, uint32_t* p_outputlength);
I_EXPORT int i_enc_final(I_CIPHER_CTX* p_context, uint8_t* p_output, uint32_t* p_outputlength);
I_EXPORT int i_dec_init(I_CIPHER_CTX* p_context, const int p_cipher_id, uint8_t* p_key, uint32_t p_keylength, const EDGE_CIPHER_PARAMETERS* p_param);
I_EXPORT int i_dec_update(I_CIPHER_CTX* p_context, uint8_t* p_input, uint32_t p_inputlength, uint8_t* p_output, uint32_t* p_outputlength);
I_EXPORT int i_dec_final(I_CIPHER_CTX* p_context, uint8_t* p_output, uint32_t* p_outputlength, uint32_t* p_paddingLength);
