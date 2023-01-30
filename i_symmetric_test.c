#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "edge_crypto.h"
#include "i_symmetric.h"

/////////////////////////////////////header of function///////////////////////////////////////////////////
int origin_sample(int 	p_cipher_id,
	uint8_t* p_key,
	uint32_t 	p_keylength,
	uint8_t* p_input,
	uint32_t 	p_inputlength,
	uint8_t* p_output,
	uint32_t* p_outputlength,
	uint8_t* p_iv,
	uint32_t    p_ivlength,
	uint32_t	blockmode);

//keyword 'i' is ybkim's signature
int i_enc_dec_sample(uint8_t* p_input, uint32_t p_inputlength, uint32_t blockmode);
int i_init_update_final_sample(uint8_t* p_input, uint32_t p_inputlength, uint32_t blockmode);
int i_init_update_final_file_sample(uint32_t blockmode);

///////////////////////////////////////////////main///////////////////////////////////////////////////////
int main(void) {
	int     ret = 0;

	EDGE_CIPHER_PARAMETERS  param;
	uint8_t* input = "test text samplesample text testa";
	uint32_t     inputlength = 33;
	uint8_t buffer[32] = { '\0', };

	int option = 0;

	ret = edge_crypto_init(NULL);
	if (ret != 0) {
		print_result("edge_crypto_init", ret);
		return ret;
	}

	memset(&param, 0, sizeof(EDGE_CIPHER_PARAMETERS));

	//select cbc or ctr
	while (option != 1 && option != 2) {
		printf("옵션 선택(1. CBC, 2. CTR) : ");
		scanf("%d", &option);
	}
	if (option == 1)
		param.m_mode = EDGE_CIPHER_MODE_CBC;
	else
		param.m_mode = EDGE_CIPHER_MODE_CTR;

	//sample
	ret = i_enc_dec_sample(input, inputlength, param.m_mode);
	if (ret != 0) return ret;
	ret = i_init_update_final_sample(input, inputlength, param.m_mode);
	if (ret != 0) return ret;
	ret = i_init_update_final_file_sample(param.m_mode);
	if (ret != 0) return ret;

	edge_crypto_final();
	return 0;
}

////////////////////////////////////////////////////definition///////////////////////////////////////////////////////////////////////
int origin_sample(int 	p_cipher_id, //sample_of_original_cbc
	uint8_t* p_key,
	uint32_t    p_keylength,
	uint8_t* p_input,
	uint32_t    p_inputlength,
	uint8_t* p_output,
	uint32_t* p_outputlength,
	uint8_t* p_iv,
	uint32_t    p_ivlength,
	uint32_t	blockmode) {

	int     ret = 0;

	EDGE_CIPHER_PARAMETERS  param;

	memset(&param, 0, sizeof(EDGE_CIPHER_PARAMETERS));

	param.m_mode = blockmode;
	param.m_padding = EDGE_CIPHER_PADDING_PKCS5;

	memcpy(param.m_modeparam.m_iv, p_iv, p_ivlength);
	param.m_modeparam.m_ivlength = p_ivlength;

	printf("\n##======================   origin_sample() start   ======================##\n");
	hexdump("input", p_input, p_inputlength);
	printf(" *----------------------         edge_enc()         ------------------------\n");

	ret = edge_enc(p_cipher_id, p_key, p_keylength, &param, p_input, p_inputlength, p_output, p_outputlength);
	print_result("edge_enc", ret);
	if (ret != 0)	return ret;
	hexdump("output", p_output, *p_outputlength);

	printf("##======================    origin_sample() end    ======================##\n");

	return ret;
}

int i_enc_dec_sample(uint8_t* p_input, uint32_t p_inputlength, uint32_t blockmode) {
	int ret = 0;

	EDGE_CIPHER_PARAMETERS  param;

	int          cipher_id = EDGE_CIPHER_ID_ARIA128;
	uint8_t      key[16] = { 0x00, };
	uint32_t     keylength = 16;
	uint8_t      iv[16] = { 0x00, };
	uint32_t     ivlength = 16;
	uint8_t      output[32] = {0x00, };//= { 0x00, };
	uint32_t     outputlength = 0;
	uint8_t      output2[1024];// = { 0x00, };
	uint32_t     output2length = 0;
	uint8_t		 decdata[1024];
	uint32_t	 decdatalength = 0;

	memset(&param, 0, sizeof(EDGE_CIPHER_PARAMETERS));

	keylength = 16;
	ivlength = 16;

	param.m_mode = blockmode;
	param.m_padding = EDGE_CIPHER_PADDING_PKCS5;
	param.m_modeparam.m_modesize = 16;

	edge_random_byte(key, keylength);
	//edge_random_byte(iv, ivlength);

	memcpy(param.m_modeparam.m_iv, iv, ivlength);
	param.m_modeparam.m_ivlength = ivlength;
	printf("\n\n===============================i_enc_dec_sample_start===================================\n\n");
	ret = origin_sample(cipher_id, key, keylength, p_input, p_inputlength, output, &outputlength, iv, ivlength, blockmode);
	if(ret != 0) return ret;

	printf("\n\n==================================================================\n\n");
	ret = i_enc(cipher_id, key, keylength, &param, p_input, p_inputlength, output2, &output2length);
	if (ret != 0) return ret;
	printf("\n\n==================================================================\n\n");
	ret = i_dec(cipher_id, key, keylength, &param, output2, output2length, decdata, &decdatalength);
	if (ret != 0) return ret;
	printf("\n=================================i_enc_dec_sample_end=====================================\n\n\n\n\n\n");

	return ret;
}

int i_init_update_final_sample(uint8_t* p_input, uint32_t p_inputlength, uint32_t blockmode) {
	int ret = 0;
	EDGE_CIPHER_PARAMETERS  param;
	I_CIPHER_CTX* ctx;

	int          cipher_id = EDGE_CIPHER_ID_ARIA128;
	uint8_t      key[16] = { 0x00, };
	uint32_t     keylength = 16;
	uint8_t      iv[16] = { 0x00, };
	uint32_t     ivlength = 16;
	uint8_t      output[1024] = { 0x00, };
	uint32_t     outputlength = 0;
	uint8_t      output2[1024] = { 0x00, };
	uint32_t     output2length = 0;
	uint8_t		 decdata[1024];
	uint32_t	 decdatalength = 0;
	uint32_t	 outputtotal = 0;
	uint32_t	 dectotal = 0;
	uint32_t	 paddingLength = 0;
	memset(&param, 0, sizeof(EDGE_CIPHER_PARAMETERS));

	keylength = 16;
	ivlength = 16;

	param.m_mode = blockmode;
	param.m_padding = EDGE_CIPHER_PADDING_PKCS5;
	param.m_modeparam.m_modesize = 16;

	edge_random_byte(key, keylength);
	//edge_random_byte(iv, ivlength);

	memcpy(param.m_modeparam.m_iv, iv, ivlength);
	param.m_modeparam.m_ivlength = ivlength;
	printf("\n\n===============================i_init_update_final_start===================================\n\n");
	origin_sample(cipher_id, key, keylength, p_input, 16, output, &outputlength, iv, ivlength, blockmode);

	ctx = i_ctx_new();

	ret = i_enc_init(ctx, cipher_id, key, keylength, &param);
	if (ret != 0) return ret;

	///////////////////////////////////update/////////////////////////////////////////
	ret = i_enc_update(ctx, p_input, 3, output2, &output2length);
	if (ret != 0) {
		printf("edge_enc_update fail [%d]\n", ret);
		return ret;
	}
	outputtotal += output2length;
	printf("\n\n *----------------------      edge_enc_update()     ------------------------\n");
	hexdump("output", output2, outputtotal);

	ret = i_enc_update(ctx, p_input + 3, 13, output2 + outputtotal, &output2length);
	if (ret != 0) {
		printf("edge_enc_update fail [%d]\n", ret);
		return ret;
	}
	outputtotal += output2length;
	printf("\n *----------------------      edge_enc_update()     ------------------------\n");
	hexdump("output", output2, outputtotal);

	//ret = i_enc_update(ctx, p_input + 32, 1, output2 + outputtotal, &output2length);
	//if (ret != 0) {
	//	printf("edge_enc_update fail [%d]\n", ret);
	//	return ret;
	//}
	//outputtotal += output2length;
	//printf("\n *----------------------      edge_enc_update()     ------------------------\n");
	//hexdump("output", output2, outputtotal);

	ret = i_enc_final(ctx, output2 + outputtotal, &output2length);
	if (ret != 0) return ret;
	outputtotal += output2length;

	printf("\n *----------------------      i_enc_final()      ------------------------\n\n");
	hexdump("output", output2, outputtotal);
	/////////////////////////////////////////////////////////////////////////////////////////////////

	ret = i_dec_init(ctx, cipher_id, key, keylength, &param);
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

	ret = i_dec_update(ctx, output2 + 16, 16, decdata + dectotal, &decdatalength);
	if (ret != 0) return ret;
	dectotal += decdatalength;
	printf("\n *----------------------      i_dec_update()      ------------------------\n");
	hexdump("output", decdata, dectotal);

	ret = i_dec_final(ctx, NULL, NULL, &paddingLength);
	if (ret != 0) return ret;
	dectotal -= paddingLength;
	printf("\n *----------------------      i_dec_final()      ------------------------\n");
	hexdump("output", decdata, dectotal);

	i_ctx_free(ctx);

	printf("\n\n===============================i_init_update_final_end===================================\n\n");

	return ret;
}

int i_init_update_final_file_sample(uint32_t blockmode) {
	int ret = 0;
	EDGE_CIPHER_PARAMETERS  param;
	I_CIPHER_CTX* ctx;

	int          cipher_id = EDGE_CIPHER_ID_ARIA128;
	uint8_t		 input[1024];
	uint32_t     inputlength = 0;
	uint32_t	 bufferSize = 1024;
	uint8_t      key[16] = { 0x00, };
	uint32_t     keylength = 16;
	uint8_t      iv[16] = { 0x00, };
	uint32_t     ivlength = 16;
	uint8_t      output[2048];
	uint32_t     outputlength = 0;
	uint8_t 	 decdata[1024];
	uint32_t	 decdatalength = 0;
	uint32_t	 paddingLength = 0;
	uint32_t	 fileSize = 0;
	uint8_t*	 filename = "./data.txt";
	uint8_t		 hashCommand[128] = "md5sum ";
	int count = 0;

	FILE* fData = fopen(filename, "rb");
	FILE* fEncOutput = fopen("./encData.txt", "wb");
	FILE* fEncData;
	FILE* fDecOutput;

	if (fData == NULL || fEncOutput == NULL) {
		printf("file open error(i_init_update_final_file_sample())\n");
		return -1;
	}

	memset(&param, 0, sizeof(EDGE_CIPHER_PARAMETERS));

	keylength = 16;
	ivlength = 16;

	param.m_mode = blockmode;
	param.m_padding = EDGE_CIPHER_PADDING_PKCS5;
	param.m_modeparam.m_modesize = 16;

	edge_random_byte(key, keylength);

	memcpy(param.m_modeparam.m_iv, iv, ivlength);
	param.m_modeparam.m_ivlength = ivlength;

	fseek(fData, 0, SEEK_END); // 파일 포인터를 파일의 끝으로 이동시킴
	fileSize = ftell(fData);
	rewind(fData);

	ctx = i_ctx_new();

	printf("\n\n===============================i_init_update_final_file_sample_start===================================\n\n");
	//////////////////////////////////////enc_start///////////////////////////////////////////////
	//init
	ret = i_enc_init(ctx, cipher_id, key, keylength, &param);
	if (ret != 0) return ret;
	//update
	while (!feof(fData)) {
		inputlength = 0;
		for (int i = 0; i < bufferSize; i++) {//read data in file
			input[i] = fgetc(fData);
			inputlength++;
			count++;
			if (count == fileSize)  break;
		}
		ret = i_enc_update(ctx, input, inputlength, output, &outputlength);
		if (ret != 0) {
			printf("edge_enc_update fail [%d]\n", ret);
			return ret;
		}
		for (int i = 0; i < outputlength; i++)//write
			fprintf(fEncOutput, "%c", output[i]);
		printf("\n\n*----------------------      i_enc_update()     ------------------------\n");

		if (count == fileSize) break;
	}
	//final
	ret = i_enc_final(ctx, output, &outputlength);
	if (ret != 0) return ret;
	printf("\n *----------------------      i_enc_final()      ------------------------\n\n");

	//write final
	for (int i = 0; i < outputlength; i++)
		fprintf(fEncOutput, "%c", output[i]);

	fclose(fData);
	fclose(fEncOutput);
	//////////////////////////////////////////////enc_end/////////////////////////////

	count = 0;
	fEncData = fopen("./encData.txt", "rb");
	fDecOutput = fopen("./decData.txt", "wb");

	if (fEncData == NULL || fDecOutput == NULL) {
		printf("file open error(i_init_update_final_file_sample())\n");
		return -1;
	}

	fseek(fEncData, 0, SEEK_END); // 파일 포인터를 파일의 끝으로 이동시킴
	fileSize = ftell(fEncData);
	rewind(fEncData);
	
	memset(input, 0, inputlength);

	//////////////////////////////////////////////dec_start/////////////////////////////
	//init
	ret = i_dec_init(ctx, cipher_id, key, keylength, &param);
	if (ret != 0) return ret;
	//update
	while (!feof(fEncData)) {
		inputlength = 0;
		for (int i = 0; i < bufferSize; i++) {//read data in file
			input[i] = fgetc(fEncData);
			inputlength++;
			count++;
			if (count == fileSize)  break;
		}
		ret = i_dec_update(ctx, input, inputlength, decdata, &decdatalength);
		if (count != fileSize) {
			for (int i = 0; i < decdatalength; i++)//write
				fprintf(fDecOutput, "%c", decdata[i]);
		}
		if (ret != 0) return ret;
		printf("\n\n*----------------------      i_dec_update()      ------------------------\n");

		if (count == fileSize) break;
	}
	//final
	ret = i_dec_final(ctx, NULL, NULL, &paddingLength);
	if (ret != 0) return ret;
	printf("\n *----------------------      i_dec_final()      ------------------------\n");

	//write final
	for (int i = 0; i < decdatalength - paddingLength; i++)
		fprintf(fDecOutput, "%c", decdata[i]);

	fclose(fEncData);
	fclose(fDecOutput);
	//////////////////////////////////////////////dec_end/////////////////////////////

	i_ctx_free(ctx);

	printf("\n\n===============================i_init_update_final_file_sample_end===================================\n\n");

	strcat(hashCommand, filename);
	strcat(hashCommand, " decData.txt");
	system(hashCommand);

	return ret;
}
