/**
* @section Encoding
* UTF-8
* @author ybkim
*/
#ifndef __I_SYMMETRIC_H__
#define __I_SYMMETRIC_H__
#include "edge_crypto.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl.aes.h>
#endif
#define I_EXPORT __attribute__ ((visibility("default")))
#define I_LOCAL  __attribute__ ((visibility("hidden")))

typedef unsigned char uint8_t;
typedef unsigned int uint32_t;

/**
* @brief hex값으로 출력을 하기 위한 함수
*/
I_EXPORT void hexdump(const char* title, void* mem, unsigned int len);

/**
* @brief init_update_final을 위해 상태 정보를 저장하기 위한 구조체
*/
typedef struct I_CIPHER_CTX I_CIPHER_CTX;
/////////////////////////////////////header of function///////////////////////////////////////////////////
//keyword 'i' is ybkim's signature

/**
* @brief input 데이터 전체를 암호화하기 위한 함수
* @param p_key [in] uint8_t* 암호화를 위한 대칭키
* @param p_keyLen [in] uint32_t 대칭키의 길이
* @param p_input [in] uint8_t* 암호화할 평문 데이터
* @param p_inputLen [in] uint32_t 암호화할 데이터의 길이
* @param p_output [out] uint8_t* 암호화된 암호문
* @param p_outputLen [out] uint32_t* 암호화된 암호문의 길이
* @return int 성공시 0 실패시 그 외
*/
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
