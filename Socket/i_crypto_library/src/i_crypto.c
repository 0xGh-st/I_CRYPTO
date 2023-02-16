#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "i_crypto.h"
#ifdef _WIN32
#include <windows.h>
#else
#include <stdarg.h>
#endif
#include <time.h>

///////////////////////////////////////test_code///////////////////////////////////////////
I_EXPORT void hexdump(const char* title, void* mem, unsigned int len){
	unsigned int i = 0;
	unsigned int j = 0;
	fprintf(stdout, "-[%s](%d)\n", title, len);
	for (i = 0; i < len + ((len % 16) ? (16 - len % 16) : 0); i++){
		// print offset
		if (i % 16 == 0)
			printf("0x%08X: ", i);
		// print hex data
		if (i < len)
			printf("%02X ", 0xFF & ((char*)mem)[i]);
		else
			printf("   ");
		// print ascii dump
		if (i % 16 == (16 - 1)){
			for (j = i - (16 - 1); j <= i; j++){
				if (j >= len)
					putchar(' ');
				else if ((((char*)mem)[j] >= 32) && (((char*)mem)[j] <= 126))
					putchar(0xFF & ((char*)mem)[j]);
				else
					putchar('.');
			}
			putchar('\n');
		}
	}  // for
	puts("");
}

// for save current state
typedef struct I_CIPHER_CTX{
	int cipher_id;
	AES_KEY key;
	uint8_t  buffer[16];
	uint8_t	 bufferSize;
	uint8_t	 lastDecBlock[16];
	I_CIPHER_PARAMETERS param;
}I_CIPHER_CTX; 

I_LOCAL int enc_ecb_to_cbc(int p_cipher_id, //enc cbc_using_ecb
	AES_KEY* p_key,
	uint8_t* p_input,
	uint32_t 	p_inputlength,
	uint8_t* p_output,
	uint32_t* p_outputlength,
	uint8_t* p_iv,
	uint32_t    p_ivlength) {

	int          ret = 0;
	uint8_t      block[16]; //plain_text xor pre_enc_data
	uint32_t     blocklength = 16; //block 길이
	uint32_t     lastBlockLength = p_inputlength % blocklength;//블록단위로 나눈 후 남은 데이터 길이 ex) blocklength : 16, input : 33 -> lastBlockLength : 1
	uint8_t      ecb_output[16] = { 0x00, };
	uint32_t     dataIndex = 0; //block의 길이만큼 증가하는 데이터의 인덱스

	for (int i = 0; i < p_ivlength; i++)
		block[i] = p_input[i] ^ p_iv[i];

	//마지막 블록 전
	while ((int)dataIndex <= ((int)p_inputlength - (int)blocklength)) {
		if (dataIndex == 0)//first enc...Ek(p ^ iv)
			AES_ecb_encrypt(block, ecb_output, p_key, AES_ENCRYPT);
		else {//after first enc.... Ek(P(i) ^ C(i-1))
			for (int i = dataIndex; i < blocklength + dataIndex; i++)//plain_text xor pre_enc_data
				block[i % blocklength] = ecb_output[i % blocklength] ^ p_input[i];  //i%blocklength = 0~15
			AES_ecb_encrypt(block, ecb_output, p_key, AES_ENCRYPT);
		}
		for (int i = dataIndex; i < blocklength + dataIndex; i++)//put ecb_enc_data to output
			p_output[i] = ecb_output[i % blocklength];
		*p_outputlength += blocklength;

		dataIndex += blocklength; // 블록단위로 인덱스 갱신
	}
	return ret;
}

I_LOCAL int dec_ecb_to_cbc(int p_cipher_id, //dec cbc_using_ecb
	AES_KEY* p_key,
	uint8_t* p_input,
	uint32_t 	p_inputlength,
	uint8_t* p_output,
	uint32_t* p_outputlength,
	uint8_t* p_iv,
	uint32_t    p_ivlength) {

	int          ret = 0;
	uint8_t      block[16];
	uint32_t     blocklength = 16;
	uint8_t      ecb_output[16] = { 0x00, };
	uint32_t     dataIndex = 0; //block의 길이만큼 증가하는 데이터의 인덱스

	//Pi = D(C(i)) ^ C(i-1)
	while ((int)dataIndex < p_inputlength) {
		for (int i = dataIndex; i < blocklength + dataIndex; i++)
			block[i % blocklength] = p_input[i];  //i%blocklength = 0~15
		AES_ecb_encrypt(block, ecb_output, p_key, AES_DECRYPT);
		//xor
		for (int i = dataIndex; i < blocklength + dataIndex; i++) {
			if (dataIndex == 0)//첫블록이면 iv와 xor
				p_output[i] = ecb_output[i] ^ p_iv[i];
			else//아니면 이전 암호문과 xor
				p_output[i] = ecb_output[i % blocklength] ^ p_input[i - 16];
		}
		*p_outputlength += blocklength;

		dataIndex += blocklength; // 블록단위로 인덱스 갱신
	}

	return ret;
}

I_LOCAL int enc_ctr_mode(int 	    p_cipher_id,
	AES_KEY* p_key,
	uint8_t* p_input,
	uint32_t 	p_inputlength,
	uint8_t* p_output,
	uint32_t* p_outputlength,
	uint8_t* counter,
	uint32_t counterlength) {

	int			 ret = 0;
	uint8_t      block[16];
	uint32_t     blocklength = 16;
	uint8_t      ecb_output[16] = { 0x00, };
	uint32_t     dataIndex = 0; //block의 길이만큼 증가하는 데이터의 인덱스
	uint32_t	 blockNum = p_inputlength / blocklength;

	//마지막 블록 전까지
	for (int i = 0; i < blockNum; i++) {
		AES_ecb_encrypt(counter, ecb_output, p_key, AES_ENCRYPT);
		for (int j = dataIndex; j < blocklength + dataIndex; j++)
			p_output[j] = ecb_output[j % blocklength] ^ p_input[j];
		(*((int*)counter))++;
		*p_outputlength += blocklength;
		dataIndex += blocklength;
	}
	return ret;
}

I_LOCAL int dec_ctr_mode(int 	    p_cipher_id,
	AES_KEY* p_key,
	uint8_t* p_input,
	uint32_t 	p_inputlength,
	uint8_t* p_output,
	uint32_t* p_outputlength,
	uint8_t* counter,
	uint32_t counterlength) {

	int			 ret = 0;
	uint8_t      block[16];
	uint32_t     blocklength = 16;
	uint8_t      ecb_output[16] = { 0x00, };
	uint32_t     dataIndex = 0; //block의 길이만큼 증가하는 데이터의 인덱스
	uint32_t	 blockNum = p_inputlength / blocklength;

	for (int i = 0; i < blockNum; i++) {
		AES_ecb_encrypt(counter, ecb_output, p_key, AES_ENCRYPT);
		for (int j = dataIndex; j < blocklength + dataIndex; j++)
			p_output[j] = ecb_output[j % blocklength] ^ p_input[j];
		(*((int*)counter))++;
		*p_outputlength += blocklength;
		dataIndex += blocklength;
	}
	return ret;
}

I_EXPORT int i_enc(int p_cipher_id,
	AES_KEY* p_key,
	I_CIPHER_PARAMETERS* p_param,
	uint8_t* p_input, uint32_t p_inputlength,
	uint8_t* p_output, uint32_t* p_outputlength) {

	int     ret = 0;

	uint8_t      block[16]; //plain_text xor pre_enc_data
	uint32_t     blocklength = 16; //block 길이
	uint32_t     lastBlockLength = p_inputlength % blocklength;//블록단위로 나눈 후 남은 데이터 길이 ex) blocklength : 16, input : 33 -> lastBlockLength : 1
	uint32_t     dataIndex = 0; //block의 길이만큼 증가하는 데이터의 인덱스
	uint32_t	 blockNum = p_inputlength / blocklength + 1;//padding인덱스 포함
	uint8_t		 lastBlockpreBlock[16];

	if (p_inputlength >= blocklength) {
		switch (p_param->mode) {
		case I_CIPHER_MODE_CBC:
			ret = enc_ecb_to_cbc(p_cipher_id, p_key, p_input, blocklength * (blockNum - 1), p_output, p_outputlength, p_param->iv, p_param->ivlength);
			if (ret != 0) {
				printf("i_enc %d", ret);
				return ret;
			}
			break;
		case I_CIPHER_MODE_CTR:
			//In the CTR Mode, iv is counter
			ret = enc_ctr_mode(p_cipher_id, p_key, p_input, blocklength * (blockNum - 1), p_output, p_outputlength, p_param->iv, p_param->ivlength);
			if (ret != 0) {
				printf("i_enc %d", ret);
				return ret;
			}
			break;
		}
	}

	//마지막 블록 패딩 처리
	for (int i = 0; i < blocklength; i++) {
		if (i < lastBlockLength)//나머지 데이터
			block[i] = p_input[*p_outputlength + i];
		else//패딩
			block[i] = blocklength - lastBlockLength;
	}

	switch (p_param->mode) {
	case I_CIPHER_MODE_CBC:
		for (int i = 0; i < blocklength; i++) {
			if (blockNum > 1) //블록이 한개보다 많은면, 즉 input이 16 이상이면
				block[i] ^= p_output[*p_outputlength - blocklength + i];//이전블록
			else//즉 input_length가 blocklength 16보다 작을 경우
				block[i] ^= p_param->iv[i];
		}
		AES_ecb_encrypt(block, lastBlockpreBlock, p_key, AES_ENCRYPT);
		for (int i = 0; i < blocklength; i++)
			p_output[*p_outputlength + i] = lastBlockpreBlock[i];

		break;
	case I_CIPHER_MODE_CTR:
		AES_ecb_encrypt(p_param->iv, lastBlockpreBlock, p_key, AES_ENCRYPT);
		(*((int*)(p_param->iv)))++;
		for (int i = 0; i < blocklength; i++)
			p_output[*p_outputlength + i] = block[i] ^ lastBlockpreBlock[i];

		break;
	}
	*p_outputlength += blocklength;
	/*
	//print_result
	printf("\n##======================  enc start   ======================##\n");
	hexdump("input", p_input, p_inputlength);
	printf(" *----------------------         i_enc()         ------------------------\n");
	printf("i_enc %d \n", ret);
	hexdump("output", p_output, *p_outputlength);
	printf("##======================    enc end    ======================##\n");
	*/
	return ret;
}

I_EXPORT int i_dec(int p_cipher_id,
	AES_KEY* p_key,
	I_CIPHER_PARAMETERS* p_param,
	uint8_t* p_input, uint32_t p_inputlength,
	uint8_t* p_output, uint32_t* p_outputlength) {

	int     ret = 0;

	uint8_t      block[16]; //plain_text xor pre_enc_data
	uint32_t     blocklength = 16; //block 길이
	uint32_t     lastBlockLength = p_inputlength % blocklength;//블록단위로 나눈 후 남은 데이터 길이 ex) blocklength : 16, input : 33 -> lastBlockLength : 1
	uint32_t     dataIndex = 0; //block의 길이만큼 증가하는 데이터의 인덱스
	uint32_t	 blockNum = p_inputlength / blocklength + 1;//padding인덱스 포함
	uint8_t		 lastBlockpreBlock[16];
	uint8_t		 padding_value = 0;

	switch (p_param->mode) {
	case I_CIPHER_MODE_CBC:
		ret = dec_ecb_to_cbc(p_cipher_id, p_key, p_input, p_inputlength, p_output, p_outputlength, p_param->iv, p_param->ivlength);
		if (ret != 0) {
			printf("i_dec %d\n", ret);
			return ret;
		}
		break;
	case I_CIPHER_MODE_CTR:
		//In the CTR Mode, iv is counter
		(*((int*)p_param->iv)) -= (blockNum - 1);//enc과정에서 카운터가 증가한 값만큼 빼기
		ret = dec_ctr_mode(p_cipher_id, p_key, p_input, p_inputlength, p_output, p_outputlength, p_param->iv, p_param->ivlength);
		if (ret != 0) {
			printf("i_dec %d", ret);
			return ret;
		}
		break;
	}

	//패딩제거
	padding_value = p_output[*p_outputlength - 1];
	for (int i = 0; i < padding_value; i++) {
		if (p_output[*p_outputlength - 1 - i] != padding_value) {//패딩 값에 대한 유효성 검증(ex)if 키가 바뀌었다면 패딩 값이 달라져 에러)
			ret = -1;
			printf("i_dec %d\n", ret);
			return ret;
		}
	}
	*p_outputlength -= p_output[*p_outputlength - 1];
	/*
	//print_result
	printf("\n##======================  dec start   ======================##\n");
	hexdump("input", p_input, p_inputlength);
	printf(" *----------------------         i_dec()         ------------------------\n");
	printf("i_dec %d\n", ret);
	hexdump("output", p_output, *p_outputlength);
	printf("##======================    dec end    ======================##\n");
	*/
	return ret;
}

I_EXPORT I_CIPHER_CTX* i_ctx_new() {//초기 설정 : iv->0x00, key->random, cipher_id->I_CIPHER_ID_ARIA128, padding->pkcs5
	I_CIPHER_CTX* return_I_CIPHER_CTX = (I_CIPHER_CTX*)malloc(sizeof(I_CIPHER_CTX));
	if (return_I_CIPHER_CTX == NULL) {
		printf("i_ctx_new() : 메모리 할당 실패\n");
		return return_I_CIPHER_CTX;
	}
	memset(return_I_CIPHER_CTX, 0, sizeof(I_CIPHER_CTX));
	return return_I_CIPHER_CTX;
}

I_EXPORT void i_ctx_reset(I_CIPHER_CTX* p_context) {
	if (p_context == NULL) {
		printf("i_ctx_reset() : 매개변수 오류\n");
		return;
	}
    memset(p_context, 0, sizeof(I_CIPHER_CTX));
	memset(&(p_context->key), 0, sizeof(AES_KEY));
	memset(&(p_context->param), 0, sizeof(I_CIPHER_PARAMETERS));
	memset(p_context->param.iv, 0, p_context->param.ivlength);
	return;
}

I_EXPORT void i_ctx_free(I_CIPHER_CTX* p_context) {
	if (p_context == NULL) {
		printf("i_ctx_free() : 매개변수 오류\n");
		return;
	}
	free(p_context);
}

I_EXPORT int i_enc_init(I_CIPHER_CTX* p_context, const int p_cipher_id, uint8_t* p_key, const I_CIPHER_PARAMETERS* p_param) {
	if (p_context == NULL) {
		printf("i_enc_init() : 매개변수 오류\n");
		return -1;
	}

	memset(&(p_context->buffer), 0, 16);
	memset(&(p_context->lastDecBlock), 0, 16);

	p_context->cipher_id = p_cipher_id;
	p_context->bufferSize = 0;

	if(AES_set_encrypt_key(p_key, 128, &(p_context->key)) < 0){
		printf("i_enc_init() key 생성 오류\n");
		return 0;
	}

	p_context->param.mode = p_param->mode;
	p_context->param.ivlength = p_param->ivlength;
	memcpy(p_context->param.iv, p_param->iv, p_context->param.ivlength);

	return 0;
}

I_EXPORT int i_enc_update(I_CIPHER_CTX* p_context, uint8_t* p_input, uint32_t p_inputlength, uint8_t* p_output, uint32_t* p_outputlength) {
	int     ret = 0;

	uint8_t      block[16]; //plain_text xor pre_enc_data
	uint32_t     blocklength = 16; //block 길이
	uint32_t	 remainLength = 0; //암호화하고 남은 input 데이터의 길이
	uint32_t	 index = 0;
	uint32_t 	 remainDataStartIndex = 0;//암호화하거나 버퍼에 쌓을 input 데이터의 시작점
	
	*p_outputlength = 0;//update시 p_outputlength는 0으로 초기화
	remainLength = p_inputlength;
	index = p_context->bufferSize;
	if (p_context->bufferSize != 0 || p_inputlength < blocklength) {//버퍼가 비어있지 않거나 input이 blocklength보다 작으면 버퍼부터 채운다.
		for (int i = index; i < blocklength; i++) {
			if (i-index == p_inputlength) break;
			p_context->buffer[i] = p_input[i - index];
			p_context->bufferSize++;
			remainLength--;
			remainDataStartIndex++;
		}
	}

	while(p_context->bufferSize == blocklength || remainLength >= 16){//버퍼가 블록단위로 가득 찼거나, 블록에 넣고 남은 데이터가 blocklength 보다 크면 암호화 진행
		switch (p_context->param.mode) {
		case I_CIPHER_MODE_CBC:
			if(p_context->bufferSize == blocklength){//우선 버퍼가 찼으면 버퍼부터 암호화
				for(int i=0;i<p_context->param.ivlength;i++)//iv는 초기벡터이거나 이전 암호문
					p_context->buffer[i] ^= p_context->param.iv[i];
				AES_ecb_encrypt(p_context->buffer, p_output, &(p_context->key), AES_ENCRYPT);
				p_context->bufferSize = 0;//버퍼는 암호화했으므로 0 초기화
			}
			else{//버퍼가 비어있고 남은 데이터가 16보다 길면
				for(int i=remainDataStartIndex;i<remainDataStartIndex+blocklength;i++)//iv는 초기벡터이거나 이전 암호문
					block[i - remainDataStartIndex] = p_input[i] ^ p_context->param.iv[i-remainDataStartIndex];
				AES_ecb_encrypt(block, p_output + *p_outputlength, &(p_context->key), AES_ENCRYPT);
				remainLength -= blocklength;
				remainDataStartIndex += blocklength;
			}
			for (int i = 0; i < p_context->param.ivlength; i++)//첫블록 이후 iv는 이전 암호문
				p_context->param.iv[i] = p_output[*p_outputlength + i];
			break;
		case I_CIPHER_MODE_CTR:
			printf("test...\n");
			//CTR mode -> counter부터 암호화
			AES_ecb_encrypt(p_context->param.iv, p_output + *p_outputlength, &(p_context->key), AES_ENCRYPT);
			if (p_context->bufferSize == blocklength){
				for(int i=0;i<blocklength;i++)
					p_output[i] ^= p_context->buffer[i];
				p_context->bufferSize = 0;
			}
			else{
				for(int i=0;i<blocklength;i++)
					p_output[i + *p_outputlength] ^= p_input[i + remainDataStartIndex];
				remainLength -= blocklength;
				remainDataStartIndex += blocklength;
			}
			break;
		}
		*p_outputlength += blocklength;//암호화가 되었다면 outputlength 증가
	}
	//버퍼에 남은 데이터 저장
	for (int i = remainDataStartIndex; i < remainDataStartIndex + remainLength; i++) {
		p_context->buffer[i - remainDataStartIndex] = p_input[i];
		p_context->bufferSize++;
	}
	return ret;
}

I_EXPORT int i_enc_final(I_CIPHER_CTX* p_context, uint8_t* p_output, uint32_t* p_outputlength) {
	int     ret = 0;

	uint8_t      block[16]; 
	uint32_t     blocklength = 16; 

	*p_outputlength = 0;

	//마지막 블록 패딩 처리
	for (int i = 0; i < blocklength; i++) {
		if (i < p_context->bufferSize)//나머지 데이터 길이
			block[i] = p_context->buffer[i];//버퍼에 암호화가 안된 나머지 데이터가 있으므로
		else//패딩
			block[i] = blocklength - (p_context->bufferSize);
	}

	switch (p_context->param.mode) {
	case I_CIPHER_MODE_CBC:
		for (int i = 0; i < blocklength; i++) 
			block[i] ^= p_context->param.iv[i];//첫블록에 대해선 기존 iv, 첫블록 이후 블록이면 iv는 이전 암호문
		AES_ecb_encrypt(block, p_output, &(p_context->key), AES_ENCRYPT);
		break;
	case I_CIPHER_MODE_CTR:
		AES_ecb_encrypt(p_context->param.iv, p_output, &(p_context->key), AES_ENCRYPT);
		for (int i = 0; i < blocklength; i++)
			p_output[i] ^= block[i];
		break;
	}
	*p_outputlength += blocklength;
	return ret;
}

I_EXPORT int i_dec_init(I_CIPHER_CTX* p_context, const int p_cipher_id, uint8_t* p_key, const I_CIPHER_PARAMETERS* p_param) {
	if (p_context == NULL) {
		printf("i_enc_init() : 매개변수 오류\n");
		return -1;
	}

	memset(&(p_context->buffer), 0, 16);
	memset(&(p_context->lastDecBlock), 0, 16);
	
	p_context->cipher_id = p_cipher_id;
	p_context->bufferSize = 0;
	if(p_param->mode == I_CIPHER_MODE_CTR){//ctr모드이면 encrypt키로 키 설정
		if(AES_set_encrypt_key(p_key, 128, &(p_context->key)) < 0){
			printf("i_enc_init() key 생성 오류\n");
			return 0;
		}
	}
	else{
		if(AES_set_decrypt_key(p_key, 128, &(p_context->key)) < 0){
			printf("i_dec_init() key 생성 오류\n");
			return 0;
		}
	}
	
	p_context->param.mode = p_param->mode;
	p_context->param.ivlength = p_param->ivlength;
	memcpy(p_context->param.iv, p_param->iv, p_context->param.ivlength);

	return 0;
}

I_EXPORT int i_dec_update(I_CIPHER_CTX* p_context, uint8_t* p_input, uint32_t p_inputlength, uint8_t* p_output, uint32_t* p_outputlength) {
	int     ret = 0;

	uint8_t      block[16]; //plain_text xor pre_enc_data
	uint32_t     blocklength = 16; //block 길이
	uint32_t	 remainLength = 0;
	uint32_t	 index = 0;
	uint32_t 	 remainDataStartIndex = 0;

	*p_outputlength = 0;//update시 p_outputlength는 0으로 초기화
	remainLength = p_inputlength;
	index = p_context->bufferSize;
	if (p_context->bufferSize != 0 || p_inputlength < blocklength) {//버퍼가 비어있지 않거나 input이 blocklength보다 작으면 버퍼부터 채운다.
		for (int i = index; i < blocklength; i++) {
			if (i - index == p_inputlength) break;
			p_context->buffer[i] = p_input[i - index];
			p_context->bufferSize++;
			remainLength--;
			remainDataStartIndex++;
		}
	}
	while (p_context->bufferSize == blocklength || remainLength >= 16) {//버퍼가 가득 찼을 경우
		switch (p_context->param.mode) {
		case I_CIPHER_MODE_CBC:
			if (p_context->bufferSize == blocklength) {//우선 버퍼가 찼으면 버퍼부터 암호화
				AES_ecb_encrypt(p_context->buffer, p_output, &(p_context->key), AES_DECRYPT);
				//iv(초기벡터, 혹은 이전 암호문)와 p_output의 결과값은 xor, 동시에 iv 이전 암호문 저장
				for (int i = 0; i < blocklength; i++){
					p_output[i] ^= p_context->param.iv[i];
					p_context->param.iv[i] = p_context->buffer[i];
				}
				p_context->bufferSize = 0;
			}
			else {
				AES_ecb_encrypt(p_input + remainDataStartIndex, p_output + *p_outputlength, &(p_context->key), AES_DECRYPT);
				for (int i = 0; i < blocklength; i++){
					p_output[i + *p_outputlength] ^= p_context->param.iv[i];
					p_context->param.iv[i] = p_input[i+remainDataStartIndex];
				}
				remainLength -= blocklength;
				remainDataStartIndex += blocklength;
			}
			break;
		case I_CIPHER_MODE_CTR:
			AES_ecb_encrypt(p_context->param.iv, p_output + *p_outputlength, &(p_context->key), AES_ENCRYPT);
			if (p_context->bufferSize == blocklength){//우선 버퍼가 찼으면 버퍼부터 복호화
				for(int i=0;i<blocklength;i++)
					p_output[i] ^= p_context->buffer[i];
				p_context->bufferSize = 0;
			}
			else{
				for(int i=0;i<blocklength;i++)
					p_output[i + *p_outputlength] ^= p_input[i + remainDataStartIndex];
				remainLength -= blocklength;
				remainDataStartIndex += blocklength;
			}
			break;
		}
		*p_outputlength += blocklength; //복호화가 진행되었다면 outputlength 증가
	}
	//복호화가 한번이라도 진행되었다면 마지막 복호문 저장 
	if(*p_outputlength >= 16)
		for (int i = 0; i < blocklength; i++)//마지막 복호문 저장
			p_context->lastDecBlock[i] = p_output[*p_outputlength - blocklength + i];
	//버퍼에 남은 데이터 저장
	for (int i = remainDataStartIndex; i < remainDataStartIndex + remainLength; i++) {
		p_context->buffer[i - remainDataStartIndex] = p_input[i];
		p_context->bufferSize++;
	}
	return ret;
}

I_EXPORT int i_dec_final(I_CIPHER_CTX* p_context, uint32_t* p_paddinglength) {
	int ret = 0;
	
	*p_paddinglength = p_context->lastDecBlock[16 - 1];//패딩값 저장
	for (int i = 0; i < *p_paddinglength; i++) {
		if (p_context->lastDecBlock[16 - 1 - i] != *p_paddinglength) {//패딩 값에 대한 유효성 검증(마지막 복호문에서 패딩 검증)
			ret = -1;
			printf("i_dec_final() failed... %d\n", ret);
			return ret;
		}
	}
	return ret;
}
 

int padding = RSA_PKCS1_PADDING;

I_EXPORT RSA * createRSA(unsigned char * key, int public){
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1); // 읽기 전용 메모리 만들기 BIO
    if (keybio==NULL){
        printf( "Failed to create key BIO");
        return 0;
    }
    /* PEM형식인 키 파일을 읽어와서 RSA 구조체 형식으로 변환 */
    if(public){ // PEM public 키로 RSA 생성
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    }
	else{ // PEM private 키로 RSA 생성
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }
    if(rsa == NULL)
        printf( "Failed to create RSA");
 
    return rsa;
}

//RSA 암복호화를 위한 함수
/* 공개키로 암호화 */
I_EXPORT int public_encrypt(unsigned char * data, int data_len, unsigned char * key, unsigned char *encrypted) {
    RSA * rsa = createRSA(key,1);
    int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
    return result; // RSA_public_encrypt() returns the size of the encrypted data 
}
/* 개인키로 복호화 */
I_EXPORT int private_decrypt(unsigned char * enc_data, int data_len, unsigned char * key, unsigned char *decrypted){
    RSA * rsa = createRSA(key,0);
    int  result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa,padding);
    return result;
}
