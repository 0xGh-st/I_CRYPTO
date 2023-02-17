#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "i_crypto.h"

/////////////////////////////////////header of function///////////////////////////////////////////////////
int origin_sample(int 	p_cipher_id,
	AES_KEY* encKey,
	AES_KEY* decKey,
	uint8_t* p_input,
	uint32_t 	p_inputlength,
	uint8_t* p_output,
	uint32_t* p_outputlength,
	uint8_t* p_iv,
	uint32_t    p_ivlength,
	uint32_t	blockmode);

//keyword 'i' is ybkim's signature
int i_enc_dec_sample(uint8_t* p_input, uint32_t p_inputlength, int blockmode);
int i_init_update_final_sample(uint8_t* p_input, uint32_t p_inputlength, int blockmode);
//int i_init_update_final_file_sample(int blockmode);

///////////////////////////////////////////////main///////////////////////////////////////////////////////
int main(void) {
	int     ret = 0;

	I_CIPHER_PARAMETERS  param;
	uint8_t* input = "test text samplesample text testa";
	uint32_t     inputlength = 33;

	ret = i_enc_dec_sample(input, inputlength, I_CIPHER_MODE_CBC);
	if(ret != 0) return ret;
	ret = i_init_update_final_sample(input, inputlength, I_CIPHER_MODE_CBC);
	if(ret != 0) return ret;
	
	return 0;
}

////////////////////////////////////////////////////definition///////////////////////////////////////////////////////////////////////
int origin_sample(int 	p_cipher_id, //sample_of_original_cbc
	AES_KEY* encKey,
	AES_KEY* decKey,
	uint8_t* p_input,
	uint32_t    p_inputlength,
	uint8_t* p_output,
	uint32_t* p_outputlength,
	uint8_t* p_iv,
	uint32_t    p_ivlength,
	uint32_t	blockmode) {

	int     ret = 0;

	I_CIPHER_PARAMETERS param;
	uint8_t decData[48] = {0x00, };

	memset(&param, 0, sizeof(I_CIPHER_PARAMETERS));
	memcpy(param.iv, p_iv, p_ivlength);

	printf("\n##======================   origin_sample() start   ======================##\n");
	hexdump("input", p_input, p_inputlength);
	
	printf(" *----------------------         AES_cbc_encrypt()         ------------------------\n");
	AES_cbc_encrypt( p_input, p_output, p_inputlength, encKey, param.iv, AES_ENCRYPT);
	*p_outputlength = ((p_inputlength/16 + 1) * 16);
	hexdump("output", p_output, *p_outputlength);

	printf(" *----------------------         AES_cbc_decrypt()         ------------------------\n");
	memcpy(param.iv, p_iv, p_ivlength);//cbc_encrypt에서 iv를 변경하므로
	AES_cbc_encrypt( p_output, decData, *p_outputlength, decKey, param.iv, AES_DECRYPT);
	hexdump("output", decData, *p_outputlength);
	printf("##======================    origin_sample() end    ======================##\n");

	return ret;
}

int i_enc_dec_sample(uint8_t* p_input, uint32_t p_inputlength, int blockmode) {
	int ret = 0;

	I_CIPHER_PARAMETERS  param;

	int          cipher_id = I_CIPHER_ID_AES128;
	uint8_t 	 zeroKey[16] = {0x00, };
	AES_KEY      encKey;
	AES_KEY		 decKey;
	uint8_t      output[64] = {0x00, };//= { 0x00, };
	uint32_t     outputlength = 0;
	uint8_t      output2[1024];// = { 0x00, };
	uint32_t     output2length = 0;
	uint8_t		 decdata[1024];
	uint32_t	 decdatalength = 0;

	memset(&encKey, 0, sizeof(AES_KEY));
	memset(&decKey, 0, sizeof(AES_KEY));
	memset(&param, 0, sizeof(I_CIPHER_PARAMETERS));
	param.ivlength = 16;
	memset(param.iv, 0, param.ivlength);

	param.mode = blockmode;

	//암복호화 키 생성
	if(AES_set_encrypt_key(zeroKey, 128, &encKey) < 0){
		printf("encKey 생성 오류\n");
		return 0;
	}
	if(param.mode == I_CIPHER_MODE_CTR){
		if(AES_set_encrypt_key(zeroKey, 128, &decKey) < 0){
			printf("decKey 생성 오류\n");
			return 0;
		}
	}
	else{
		if(AES_set_decrypt_key(zeroKey, 128, &decKey) < 0){
			printf("decKey 생성 오류\n");
			return 0;
		}
	}
	
	printf("\n\n===============================i_enc_dec_sample_start===================================\n\n");
	if(param.mode == I_CIPHER_MODE_CBC){//openssl 샘플은 cbc만 지원합니다.
		//기존 openssl을 이용한 cbc 암복호화 예시
		ret = origin_sample(cipher_id, &encKey, &decKey, p_input, p_inputlength, output, &outputlength, param.iv, param.ivlength, blockmode);
		if(ret != 0) return ret;
		printf("\n\n==================================================================\n\n");
	}
	//openssl에서 AES_ecb_encrypt만을 이용하여 직접 구현한 암호화
	ret = i_enc(cipher_id, &encKey, &param, p_input, p_inputlength, output2, &output2length);
	if (ret != 0) return ret;
	printf("\n\n==================================================================\n\n");
	
	//openssl에서 AES_ecb_encrypt만을 이용하여 직접 구현한 복호화
	ret = i_dec(cipher_id, &decKey, &param, output2, output2length, decdata, &decdatalength);
	if (ret != 0) return ret;
	
	printf("\n=================================i_enc_dec_sample_end=====================================\n\n\n\n\n\n");

	return ret;
}

int i_init_update_final_sample(uint8_t* p_input, uint32_t p_inputlength, int blockmode) {
	int ret = 0;

	I_CIPHER_PARAMETERS  param;

	int          cipher_id = I_CIPHER_ID_AES128;
	uint8_t 	 zeroKey[16] = {0x00, };
	AES_KEY      encKey;
	AES_KEY		 decKey;
	uint8_t      output[64] = {0x00, };//= { 0x00, };
	uint32_t     outputlength = 0;
	uint8_t      output2[1024];// = { 0x00, };
	uint32_t     output2length = 0;
	uint8_t		 decdata[1024];
	uint32_t	 decdatalength = 0;
	uint32_t 	 outputtotal = 0;
	uint32_t	 dectotal = 0;
	uint32_t	 paddinglength = 0;
	void* 		 ctx = NULL;

	memset(&encKey, 0, sizeof(AES_KEY));
	memset(&decKey, 0, sizeof(AES_KEY));
	memset(&param, 0, sizeof(I_CIPHER_PARAMETERS));
	param.ivlength = 16;
	memset(param.iv, 0, param.ivlength);

	param.mode = blockmode;

	printf("\n\n===============================i_init_update_final_start===================================\n\n");

	ctx = i_ctx_new();

	ret = i_enc_init(ctx, cipher_id, zeroKey, &param);
	if (ret != 0) return ret;


	///////////////////////////////////enc update/////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////
	ret = i_enc_update(ctx, p_input, 3, output2, &output2length);
	if (ret != 0) {
		printf("I_enc_update fail [%d]\n", ret);
		return ret;
	}
	outputtotal += output2length;
	printf("\n\n *----------------------      I_enc_update()     ------------------------\n");
	hexdump("output", output2, outputtotal);

	ret = i_enc_update(ctx, p_input + 3, 13, output2 + outputtotal, &output2length);
	if (ret != 0) {
		printf("I_enc_update fail [%d]\n", ret);
		return ret;
	}
	outputtotal += output2length;
	printf("\n *----------------------      I_enc_update()     ------------------------\n");
	hexdump("output", output2, outputtotal);

	ret = i_enc_update(ctx, p_input + 16, 17, output2 + outputtotal, &output2length);
	outputtotal += output2length;
	printf("\n *----------------------      I_enc_update()     ------------------------\n");
	hexdump("output", output2, outputtotal);
	ret = i_enc_final(ctx, output2 + outputtotal, &output2length);
	if (ret != 0) return ret;
	outputtotal += output2length;

	printf("\n *----------------------      i_enc_final()      ------------------------\n\n");
	hexdump("output", output2, outputtotal);



	///////////////////////////////////dec update////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////
	ret = i_dec_init(ctx, cipher_id, zeroKey, &param);
	if (ret != 0) return ret;

	ret = i_dec_update(ctx, output2, 3, decdata, &decdatalength);
	if (ret != 0) return ret;
	dectotal += decdatalength;
	printf("\n\n\n\n\n *----------------------      i_dec_update()      ------------------------\n");
	hexdump("output", decdata, dectotal);
	
	ret = i_dec_update(ctx, output2 + 3, 13, decdata + dectotal, &decdatalength);
	if (ret != 0) return ret;
	dectotal += decdatalength;
	printf("\n *----------------------      i_dec_update()      ------------------------\n");
	hexdump("output", decdata, dectotal);

	ret = i_dec_update(ctx, output2 + 16, 32, decdata + dectotal, &decdatalength);
	if (ret != 0) return ret;
	dectotal += decdatalength;
	printf("\n *----------------------      i_dec_update()      ------------------------\n");
	hexdump("output", decdata, dectotal);

	ret = i_dec_final(ctx, &paddinglength);
	if (ret != 0) return ret;
	dectotal -= paddinglength;
	printf("\n *----------------------      i_dec_final()      ------------------------\n");
	hexdump("output", decdata, dectotal);


	/////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////
	i_ctx_free(ctx);

	printf("\n\n===============================i_init_update_final_end===================================\n\n");

	return ret;
}