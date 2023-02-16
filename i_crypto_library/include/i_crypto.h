/**
* @section Encoding
* UTF-8
* @author ybkim
*/

#ifndef __I_SYMMETRIC_H__
#define __I_SYMMETRIC_H__
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/aes.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
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
 * @brief 지원하는 암호 알고리즘
 */
#define I_CIPHER_ID 0
#define I_CIPHER_ID_AES128 I_CIPHER_ID + 1

/**
 * @brief 지원하는 블록암호 운용모드
 */
typedef enum {
    I_CIPHER_MODE_CBC                                    = 1, // 블록암호 운용모드 CBC    
    I_CIPHER_MODE_CTR                                         // 블록암호 운용모드 CTR  
} I_CIPHER_MODE;

/**
 * @brief init_update_final을 위해 내부적으로 상태 정보를 저장하는 구조체
*/
typedef struct I_CIPHER_CTX I_CIPHER_CTX;

/**
 * @brief 암복호화를 위해 필요한 파라미터 구조체
*/
typedef struct I_CIPHER_PARAMETERS{
	int mode;
	uint8_t iv[16];
	uint32_t ivlength;
} I_CIPHER_PARAMETERS;

/**
 * @brief input 데이터 전체를 암호화하기 위한 함수
 * @param p_key [in] AES_KEY* 암호화를 위한 대칭키
 * @param p_param [in] I_CIPHER_PARAMETERS* 암복호화를 위해 필요한 파라미터
 * @param p_input [in] uint8_t* 암호화할 평문 데이터
 * @param p_inputLen [in] uint32_t 암호화할 데이터의 길이
 * @param p_output [out] uint8_t* 암호화된 암호문
 * @param p_outputLen [out] uint32_t* 암호화된 암호문의 길이
 * @return int 성공시 0 실패시 그 외
*/
I_EXPORT int i_enc						(int p_cipherId,
										 AES_KEY* p_key,
										 I_CIPHER_PARAMETERS* p_param,
										 uint8_t* p_input, uint32_t p_inputLen,
										 uint8_t* p_output, uint32_t* p_outputLen);

/**
 * @brief input 데이터 전체를 복호화하기 위한 함수
 * @param p_key [in] AES_KEY* 암호화를 위한 대칭키
 * @param p_param [in] I_CIPHER_PARAMETERS* 암복호화를 위해 필요한 파라미터
 * @param p_input [in] uint8_t* 복호화할 평문 데이터
 * @param p_inputLen [in] uint32_t 복호화할 데이터의 길이
 * @param p_output [out] uint8_t* 복호화된 평문문
 * @param p_outputLen [out] uint32_t* 복호화된 평문의 길이
 * @return int 성공시 0 실패시 그 외
*/
I_EXPORT int i_dec						(int p_cipherId,
										 AES_KEY* p_key, 
										 I_CIPHER_PARAMETERS* p_param,
										 uint8_t* p_input, uint32_t p_inputLen,
										 uint8_t* p_output, uint32_t* p_outputLen);
	
/**
* @brief 내부적으로 상태정보를 저장하는 context 구조체를 생성하여 반환
* @return I_CIPHER_CTX* 실패시 NULL
*/
I_EXPORT I_CIPHER_CTX* i_ctx_new();

/**
 * @brief context 구조체 초기화 함수
 * @details init, update, final 이 후 context를 재사용하려면 반드시 reset되어야 한다.
*/
I_EXPORT void i_ctx_reset				(I_CIPHER_CTX* p_context);

/**
 * @brief i_ctx_new()로 생성한 context구조체 메모리 해제 함수
*/
I_EXPORT void i_ctx_free				(I_CIPHER_CTX* p_context);

/**
 * @brief 대칭키 암호화를 위해 사용할 context 설정 함수
 * @param p_context [in] I_CIPHER_CTX* 내부적으로 상태 정보를 저장하는 context
 * @param p_cipher_id [in] const int 대칭키 암호 알고리즘
 * @param p_key [in] uint8_t* 대칭키
 * @param p_param [in] I_CIPHER_PARAMETERS* 암호화에 사용될 정보를 담고 있는 파라미터
*/
I_EXPORT int i_enc_init					(I_CIPHER_CTX* p_context, 
										 const int p_cipher_id, 
										 uint8_t* p_key,  
										 const I_CIPHER_PARAMETERS* p_param);

/**
 * @brief 데이터를 암호화하기 위한 입력 함수
 * @details 데이터를 모두 업데이트 했으면 반드시 i_enc_final()을 수행하여야 함
 * @param p_context [in] I_CIPHER_CTX* 내부적으로 상태 정보를 저장하는 context
 * @param p_input [in] uint8_t* 암호화할 평문
 * @param p_inputlength [in] uint32_t 암호화할 평문의 길이
 * @param p_output [out] uint8_t* 암호화된 암호문
 * @param p_outputLen [out] uint32_t* 암호화된 암호문의 길이
 * @return int 성공시 0 실패시 그 외
*/
I_EXPORT int i_enc_update				(I_CIPHER_CTX* p_context, 
										 uint8_t* p_input, uint32_t p_inputlength, 
										 uint8_t* p_output, uint32_t* p_outputlength);


/**
 * @brief 데이터를 암호화하기 위한 마지막 단계
 * @details 최종적으로 패딩처리를 수행, 반드시 업데이트를 완료한 상태에서 호출하여야 함
 * @param p_context [in] I_CIPHER_CTX* 내부적으로 상태 정보를 저장하는 context
 * @param p_output [out] uint8_t* 암호화된 암호문
 * @param p_outputLen [out] uint32_t* 암호화된 암호문의 길이
 * @return int 성공시 0 실패시 그 외
*/
I_EXPORT int i_enc_final				(I_CIPHER_CTX* p_context, 
										 uint8_t* p_output, uint32_t* p_outputlength);

/**
 * @brief 대칭키 복호화를 위해 사용할 context 설정 함수
 * @param p_context [in] I_CIPHER_CTX* 내부적으로 상태 정보를 저장하는 context
 * @param p_cipher_id [in] const int 대칭키 암호 알고리즘
 * @param p_key [in] uint8_t* 대칭키
 * @param p_param [in] I_CIPHER_PARAMETERS* 복호화에 사용될 정보를 담고 있는 파라미터
*/
I_EXPORT int i_dec_init					(I_CIPHER_CTX* p_context, 
										 const int p_cipher_id, 
										 uint8_t* p_key, const 
										 I_CIPHER_PARAMETERS* p_param);

/**
 * @brief 데이터를 복호화하기 위한 입력 함수
 * @details 데이터를 모두 업데이트 했으면 반드시 i_dec_final()을 수행하여야 함
 * @param p_context [in] I_CIPHER_CTX* 내부적으로 상태 정보를 저장하는 context
 * @param p_input [in] uint8_t* 복호화할 암호문
 * @param p_inputlength [in] uint32_t 복호화할 암호문의 길이
 * @param p_output [out] uint8_t* 복호화된 평문
 * @param p_outputLen [out] uint32_t* 복호화된 평문의 길이
 * @return int 성공시 0 실패시 그 외
*/
I_EXPORT int i_dec_update				(I_CIPHER_CTX* p_context, 
										 uint8_t* p_input, uint32_t p_inputlength, 
										 uint8_t* p_output, uint32_t* p_outputlength);

/**
 * @brief 데이터를 복호화하기 위한 마지막 단계
 * @details 최종적으로 패딩검증 수행, 반드시 업데이트를 완료한 상태에서 호출하여야 함
 * @param p_context [in] I_CIPHER_CTX* 내부적으로 상태 정보를 저장하는 context
 * @param p_paddinglength [out] uint32_t* 패딩 길이
 * @return int 성공시 0 실패시 그 외
*/
I_EXPORT int i_dec_final				(I_CIPHER_CTX* p_context, 
										 uint32_t* p_paddinglength);


I_EXPORT int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted);
I_EXPORT int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted);
