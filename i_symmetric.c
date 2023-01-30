#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "edge_crypto.h"
#include "i_symmetric.h"
#ifdef _WIN32
#include <windows.h>
#else
#include <stdarg.h>
#endif
#include <time.h>

///////////////////////////////////////test_code///////////////////////////////////////////
I_EXPORT const char* crypto_getStatusString(int p_status)
{
	switch (p_status) {
	case EDGE_CRYPTO_STATUS_NOT_INITIALIZED:
		return "NOT INITIALIZED";
	case EDGE_CRYPTO_STATUS_CMVP:
		return "CMVP MODE";
	case EDGE_CRYPTO_STATUS_NORMAL:
		return "NonCMVP MODE";
	case EDGE_CRYPTO_STATUS_ERROR:
		return "ERROR";
	}

	return "ERROR";
}

I_EXPORT void hexdump(const char* title, void* mem, unsigned int len)
{
	unsigned int i = 0;
	unsigned int j = 0;

	fprintf(stdout, "-[%s](%d)\n", title, len);

	for (i = 0; i < len + ((len % 16) ? (16 - len % 16) : 0); i++)
	{
		// print offset
		if (i % 16 == 0)
			printf("0x%08X: ", i);

		// print hex data
		if (i < len)
			printf("%02X ", 0xFF & ((char*)mem)[i]);

		else
			printf("   ");

		// print ascii dump
		if (i % 16 == (16 - 1))
		{
			for (j = i - (16 - 1); j <= i; j++)
			{
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

I_EXPORT void printf_red(const char* const Format, ...) {
	va_list valist;
	va_start(valist, Format);
	char buff[2048];
#ifdef _WIN32
	HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
	WORD old;
	CONSOLE_SCREEN_BUFFER_INFO csbiInfo;

	GetConsoleScreenBufferInfo(h, &csbiInfo);
	old = csbiInfo.wAttributes;

	SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_INTENSITY);
	vprintf(Format, valist);
	SetConsoleTextAttribute(h, old);
#else
	printf("\033[0;91m");
	vsprintf(buff, Format, valist);
	printf(buff);
	printf("\033[0m");
#endif
	va_end(valist);
}

I_EXPORT void print_result(const char* p_function, int p_result)
{
	if (p_result != 0) {
		printf_red("%s fail [%d]\n", p_function, p_result);
	}
	else {
		printf("%s success [%d]\n", p_function, p_result);
	}
}

// clone of EDGE_CIPHER_CTX
typedef struct I_CIPHER_CTX{
	int cipher_id;
	uint8_t key[16];
	uint32_t keylength;
	uint8_t  buffer[16];
	uint8_t	 bufferSize;
	uint8_t	 lastDecBlock[16];
	uint8_t  total;
	EDGE_CIPHER_PARAMETERS param;
}I_CIPHER_CTX; 

I_LOCAL int enc_cbc_to_ecb(int 	p_cipher_id, //enc ecb 1block using cbc
	uint8_t* p_key,
	uint32_t    p_keylength,
	uint8_t* p_input,
	uint32_t    p_inputlength,
	uint8_t* p_output,
	uint32_t* p_outputlength) {

	int ret = 0;

	EDGE_CIPHER_PARAMETERS  param;
	uint32_t     blocklength = 16;
	uint8_t      iv[16] = { 0x00, };
	uint32_t     ivlength = 0;

	memset(&param, 0, sizeof(EDGE_CIPHER_PARAMETERS));

	ivlength = 16;

	param.m_mode = EDGE_CIPHER_MODE_CBC;
	param.m_padding = EDGE_CIPHER_PADDING_NONE;

	memcpy(param.m_modeparam.m_iv, iv, ivlength);
	param.m_modeparam.m_ivlength = ivlength;

	ret = edge_enc(p_cipher_id, p_key, p_keylength, &param, p_input, p_inputlength, p_output, p_outputlength);

	return ret;
}

I_LOCAL int dec_cbc_to_ecb(int 	p_cipher_id, //dec ecb 1block using cbc
	uint8_t* p_key,
	uint32_t    p_keylength,
	uint8_t* p_input,
	uint32_t    p_inputlength,
	uint8_t* p_output,
	uint32_t* p_outputlength) {

	int ret = 0;

	EDGE_CIPHER_PARAMETERS  param;
	uint32_t     blocklength = 16;
	uint8_t      iv[16] = { 0x00, };
	uint32_t     ivlength = 0;

	memset(&param, 0, sizeof(EDGE_CIPHER_PARAMETERS));

	ivlength = 16;

	param.m_mode = EDGE_CIPHER_MODE_CBC;
	param.m_padding = EDGE_CIPHER_PADDING_NONE;

	memcpy(param.m_modeparam.m_iv, iv, ivlength);
	param.m_modeparam.m_ivlength = ivlength;

	ret = edge_dec(p_cipher_id, p_key, p_keylength, &param, p_input, p_inputlength, p_output, p_outputlength);

	return ret;
}

I_LOCAL int enc_ecb_to_cbc_pkcs5(int 	    p_cipher_id, //enc cbc_using_ecb
	uint8_t* p_key,
	uint32_t 	p_keylength,
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
	uint32_t     ecb_outputlength = 0;
	uint32_t     dataIndex = 0; //block의 길이만큼 증가하는 데이터의 인덱스

	for (int i = 0; i < p_ivlength; i++)
		block[i] = p_input[i] ^ p_iv[i];

	//마지막 블록 전
	while ((int)dataIndex <= ((int)p_inputlength - (int)blocklength)) {
		if (dataIndex == 0) {//first enc...Ek(p ^ iv)
			ret = enc_cbc_to_ecb(p_cipher_id, p_key, p_keylength, block, blocklength, ecb_output, &ecb_outputlength);
			if (ret != 0) {
				print_result("enc_ecb_to_cbc_pkcs5", ret);
				return ret;
			}
		}
		else {//after first enc.... Ek(P(i) ^ C(i-1))
			for (int i = dataIndex; i < blocklength + dataIndex; i++) {//plain_text xor pre_enc_data
				block[i % blocklength] = ecb_output[i % blocklength] ^ p_input[i];  //i%blocklength = 0~15
			}
			ret = enc_cbc_to_ecb(p_cipher_id, p_key, p_keylength, block, blocklength, ecb_output, &ecb_outputlength);
			if (ret != 0) {
				print_result("enc_ecb_to_cbc_pkcs5", ret);
				return ret;
			}
		}
		for (int i = dataIndex; i < blocklength + dataIndex; i++)//put ecb_enc_data to output
			p_output[i] = ecb_output[i % blocklength];
		*p_outputlength += blocklength;

		dataIndex += blocklength; // 블록단위로 인덱스 갱신
	}
	return ret;
}

I_LOCAL int dec_ecb_to_cbc_pkcs5(int 	    p_cipher_id, //dec cbc_using_ecb
	uint8_t* p_key,
	uint32_t 	p_keylength,
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
	uint32_t     ecb_outputlength = 0;
	uint32_t     dataIndex = 0; //block의 길이만큼 증가하는 데이터의 인덱스
	uint8_t		 padding_value = 0;

	//Pi = D(C(i)) ^ C(i-1)
	while ((int)dataIndex < p_inputlength) {
		for (int i = dataIndex; i < blocklength + dataIndex; i++) {
			block[i % blocklength] = p_input[i];  //i%blocklength = 0~15
		}
		ret = dec_cbc_to_ecb(p_cipher_id, p_key, p_keylength, block, blocklength, ecb_output, &ecb_outputlength);
		if (ret != 0) {
			print_result("dec_ecb_to_cbc_pkcs5", ret);
			return ret;
		}
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
	uint8_t* p_key,
	uint32_t 	p_keylength,
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
	uint32_t     ecb_outputlength = 0;
	uint32_t     dataIndex = 0; //block의 길이만큼 증가하는 데이터의 인덱스
	uint32_t	 blockNum = p_inputlength / blocklength;

	//마지막 블록 전까지
	for (int i = 0; i < blockNum; i++) {
		ret = enc_cbc_to_ecb(p_cipher_id, p_key, p_keylength, counter, counterlength, ecb_output, &ecb_outputlength);
		if (ret != 0) {
			print_result("enc_ctr_mode", ret);
			return ret;
		}
		for (int j = dataIndex; j < blocklength + dataIndex; j++)
			p_output[j] = ecb_output[j % blocklength] ^ p_input[j];
		(*((int*)counter))++;
		*p_outputlength += blocklength;
		dataIndex += blocklength;
	}
	return ret;
}

I_LOCAL int dec_ctr_mode(int 	    p_cipher_id,
	uint8_t* p_key,
	uint32_t 	p_keylength,
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
	uint32_t     ecb_outputlength = 0;
	uint32_t     dataIndex = 0; //block의 길이만큼 증가하는 데이터의 인덱스
	uint32_t	 blockNum = p_inputlength / blocklength;
	uint32_t	 lastBlockLength = p_inputlength % blocklength;
	uint8_t		 padding_value = 0;

	for (int i = 0; i < blockNum; i++) {
		ret = enc_cbc_to_ecb(p_cipher_id, p_key, p_keylength, counter, counterlength, ecb_output, &ecb_outputlength);//카운터모드 : 암호화와 복호화가 같음
		if (ret != 0) {
			print_result("dec_ctr_mode", ret);
			return ret;
		}
		for (int j = dataIndex; j < blocklength + dataIndex; j++)
			p_output[j] = ecb_output[j % blocklength] ^ p_input[j];
		(*((int*)counter))++;
		*p_outputlength += blocklength;
		dataIndex += blocklength;
	}
	return ret;
}

I_EXPORT int i_enc(int p_cipher_id,
	uint8_t* p_key, uint32_t p_keylength,
	EDGE_CIPHER_PARAMETERS* p_param,
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
		switch (p_param->m_mode) {
		case EDGE_CIPHER_MODE_CBC:
			ret = enc_ecb_to_cbc_pkcs5(p_cipher_id, p_key, p_keylength, p_input, blocklength * (blockNum - 1), p_output, p_outputlength, p_param->m_modeparam.m_iv, p_param->m_modeparam.m_ivlength);
			if (ret != 0) {
				print_result("i_enc", ret);
				return ret;
			}
			break;
		case EDGE_CIPHER_MODE_CTR:
			//In the CTR Mode, iv is counter
			ret = enc_ctr_mode(p_cipher_id, p_key, p_keylength, p_input, blocklength * (blockNum - 1), p_output, p_outputlength, p_param->m_modeparam.m_iv, p_param->m_modeparam.m_ivlength);
			if (ret != 0) {
				print_result("i_enc", ret);
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

	switch (p_param->m_mode) {
	case EDGE_CIPHER_MODE_CBC:
		for (int i = 0; i < blocklength; i++) {
			if (blockNum > 1) //블록이 한개보다 많은면, 즉 input이 16 이상이면
				block[i] ^= p_output[*p_outputlength - blocklength + i];//이전블록
			else//즉 input_length가 blocklength 16보다 작을 경우
				block[i] ^= p_param->m_modeparam.m_iv[i];
		}
		ret = enc_cbc_to_ecb(p_cipher_id, p_key, p_keylength, block, blocklength, lastBlockpreBlock, &lastBlockLength);
		if (ret != 0) {
			print_result("i_enc", ret);
			return ret;
		}
		for (int i = 0; i < blocklength; i++)
			p_output[*p_outputlength + i] = lastBlockpreBlock[i];

		break;
	case EDGE_CIPHER_MODE_CTR:
		ret = enc_cbc_to_ecb(p_cipher_id, p_key, p_keylength, p_param->m_modeparam.m_iv, p_param->m_modeparam.m_ivlength, lastBlockpreBlock, &lastBlockLength);
		if (ret != 0) {
			print_result("i_enc", ret);
			return ret;
		}
		(*((int*)(p_param->m_modeparam.m_iv)))++;
		for (int i = 0; i < blocklength; i++)
			p_output[*p_outputlength + i] = block[i] ^ lastBlockpreBlock[i];

		break;
	}
	*p_outputlength += blocklength;

	//print_result
	printf("\n##======================  i_enc start   ======================##\n");
	hexdump("input", p_input, p_inputlength);
	printf(" *----------------------         edge_enc()         ------------------------\n");
	print_result("i_enc", ret);
	hexdump("output", p_output, *p_outputlength);
	printf("##======================    i_enc end    ======================##\n");

	return ret;
}

I_EXPORT int i_dec(int p_cipher_id,
	uint8_t* p_key, uint32_t p_keylength,
	EDGE_CIPHER_PARAMETERS* p_param,
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

	switch (p_param->m_mode) {
	case EDGE_CIPHER_MODE_CBC:
		ret = dec_ecb_to_cbc_pkcs5(p_cipher_id, p_key, p_keylength, p_input, p_inputlength, p_output, p_outputlength, p_param->m_modeparam.m_iv, p_param->m_modeparam.m_ivlength);
		if (ret != 0) {
			print_result("i_dec", ret);
			return ret;
		}
		break;
	case EDGE_CIPHER_MODE_CTR:
		//In the CTR Mode, iv is counter
		(*((int*)p_param->m_modeparam.m_iv)) -= (blockNum - 1);//enc과정에서 카운터가 증가한 값만큼 빼기
		ret = dec_ctr_mode(p_cipher_id, p_key, p_keylength, p_input, p_inputlength, p_output, p_outputlength, p_param->m_modeparam.m_iv, p_param->m_modeparam.m_ivlength);
		if (ret != 0) {
			print_result("i_dec", ret);
			return ret;
		}
		break;
	}

	//패딩제거
	padding_value = p_output[*p_outputlength - 1];
	for (int i = 0; i < padding_value; i++) {
		if (p_output[*p_outputlength - 1 - i] != padding_value) {//패딩 값에 대한 유효성 검증(ex)if 키가 바뀌었다면 패딩 값이 달라져 에러)
			ret = -1;
			print_result("i_dec", ret);
			return ret;
		}
	}
	*p_outputlength -= p_output[*p_outputlength - 1];

	//print_result
	printf("\n##======================  i_dec start   ======================##\n");
	hexdump("input", p_input, p_inputlength);
	printf(" *----------------------         edge_dec()         ------------------------\n");
	print_result("i_dec", ret);
	hexdump("output", p_output, *p_outputlength);
	printf("##======================    i_dec end    ======================##\n");

	return ret;
}

I_EXPORT I_CIPHER_CTX* i_ctx_new() {//초기 설정 : iv->0x00, key->random, cipher_id->EDGE_CIPHER_ID_ARIA128, padding->pkcs5
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

	return;
}

I_EXPORT void i_ctx_free(I_CIPHER_CTX* p_context) {
	if (p_context == NULL) {
		printf("i_ctx_free() : 매개변수 오류\n");
		return;
	}
	free(p_context);
}

I_EXPORT int i_enc_init(I_CIPHER_CTX* p_context, const int p_cipher_id, uint8_t* p_key, uint32_t p_keylength, const EDGE_CIPHER_PARAMETERS* p_param) {
	if (p_context == NULL) {
		printf("i_enc_init() : 매개변수 오류\n");
		return -1;
	}

	memset(&(p_context->buffer), 0, 16);
	memset(&(p_context->lastDecBlock), 0, 16);
	p_context->total = 0;
	p_context->cipher_id = p_cipher_id;
	p_context->param = *p_param;
	p_context->keylength = p_keylength;
	p_context->bufferSize = 0;
	memcpy(p_context->key, p_key, p_keylength);

	return 0;
}

I_EXPORT int i_enc_update(I_CIPHER_CTX* p_context, uint8_t* p_input, uint32_t p_inputlength, uint8_t* p_output, uint32_t* p_outputlength) {
	int     ret = 0;

	uint8_t      block[16]; //plain_text xor pre_enc_data
	uint32_t     blocklength = 16; //block 길이
	uint32_t	 blockNum = 0;//padding인덱스 포함
	uint32_t	 remainLength = 0;
	uint32_t	 index = 0;

	*p_outputlength = 0;//update시 p_outputlength는 0으로 초기화
	remainLength = p_inputlength;
	index = p_context->bufferSize;
	if (p_context->bufferSize != 0 || p_inputlength < blocklength) {//버퍼가 비어있지 않거나 input이 blocklength보다 작으면 버퍼부터 채운다.
		for (int i = index; i < blocklength; i++) {
			if (i-index == p_inputlength) break;
			p_context->buffer[i] = p_input[i - index];
			p_context->bufferSize++;
			remainLength--;
		}
	}
	p_context->total += p_inputlength;

	while (p_context->bufferSize == blocklength || remainLength >= 16) {//버퍼가 블록단위로 가득 찼거나, 블록에 넣고 남은 데이터가 blocklength 보다 크면 암호화 진행
		switch (p_context->param.m_mode) {
		case EDGE_CIPHER_MODE_CBC:
			if(p_context->bufferSize == blocklength)//우선 버퍼가 찼으면 버퍼부터 암호화
				ret = enc_ecb_to_cbc_pkcs5(p_context->cipher_id, p_context->key, p_context->keylength, p_context->buffer, blocklength, p_output + (blockNum * blocklength), p_outputlength, p_context->param.m_modeparam.m_iv, p_context->param.m_modeparam.m_ivlength);
			else//버퍼가 비어있고 남은 데이터가 blocklength보다 길면
				ret = enc_ecb_to_cbc_pkcs5(p_context->cipher_id, p_context->key, p_context->keylength, p_input + (p_inputlength-remainLength), (remainLength/blocklength*blocklength), p_output + (blockNum * blocklength), p_outputlength, p_context->param.m_modeparam.m_iv, p_context->param.m_modeparam.m_ivlength);
			if (ret != 0) {
				print_result("i_enc_update", ret);
				return ret;
			}
			for (int i = 0; i < blocklength; i++)//첫블록 이후 iv는 이전 암호문
				p_context->param.m_modeparam.m_iv[i] = p_output[*p_outputlength - blocklength + i];
			break;
		case EDGE_CIPHER_MODE_CTR:
			if (p_context->bufferSize == blocklength)
				ret = enc_ctr_mode(p_context->cipher_id, p_context->key, p_context->keylength, p_context->buffer, blocklength, p_output + (blockNum * blocklength), p_outputlength, p_context->param.m_modeparam.m_iv, p_context->param.m_modeparam.m_ivlength);
			else
				ret = enc_ctr_mode(p_context->cipher_id, p_context->key, p_context->keylength, p_input + (p_inputlength - remainLength), (remainLength / blocklength * blocklength), p_output + (blockNum * blocklength), p_outputlength, p_context->param.m_modeparam.m_iv, p_context->param.m_modeparam.m_ivlength);
			if (ret != 0) {
				print_result("i_enc_update", ret);
				return ret;
			}
			break;
		}
		//남는 데이터 처리
		if (remainLength >= 16 && p_context->bufferSize == blocklength) {//buffer가 blocklength가 돼서 buffer를 먼저 암호화 한 경우
			p_context->bufferSize = 0;
			blockNum++;
			continue; 
		}
		p_context->bufferSize = 0;
		remainLength %= blocklength;//최종 남은 데이터 길이
		for (int i = 0; i < remainLength; i++) {//버퍼에 남은 데이터 저장
			p_context->buffer[i] = p_input[p_inputlength - remainLength + i];
			p_context->bufferSize++;
		}
		blockNum++;
	}
	return ret;
}

I_EXPORT int i_enc_final(I_CIPHER_CTX* p_context, uint8_t* p_output, uint32_t* p_outputlength) {
	int     ret = 0;

	uint8_t      block[16]; 
	uint32_t     blocklength = 16; 
	uint8_t		 lastBlockpreBlock[16];

	//마지막 블록 패딩 처리
	for (int i = 0; i < blocklength; i++) {
		if (i < p_context->total % blocklength)//나머지 데이터 길이
			block[i] = p_context->buffer[i];//버퍼에 암호화가 안된 나머지 데이터가 있으므로
		else//패딩
			block[i] = blocklength - (p_context->total % blocklength);
	}

	switch (p_context->param.m_mode) {
	case EDGE_CIPHER_MODE_CBC:
		for (int i = 0; i < blocklength; i++) 
			block[i] ^= p_context->param.m_modeparam.m_iv[i];//첫블록에 대해선 기존 iv, 첫블록 이후 블록이면 iv는 이전 암호문

		ret = enc_cbc_to_ecb(p_context->cipher_id, p_context->key, p_context->keylength, block, blocklength, lastBlockpreBlock, p_outputlength);
		if (ret != 0) {
			print_result("i_enc_final", ret);
			return ret;
		}

		for (int i = 0; i < blocklength; i++)
			p_output[i] = lastBlockpreBlock[i];
		break;
	case EDGE_CIPHER_MODE_CTR:
		ret = enc_cbc_to_ecb(p_context->cipher_id, p_context->key, p_context->keylength, p_context->param.m_modeparam.m_iv, p_context->param.m_modeparam.m_ivlength, lastBlockpreBlock, p_outputlength);
		if (ret != 0) {
			print_result("i_enc_final", ret);
			return ret;
		}
		for (int i = 0; i < blocklength; i++)
			p_output[i] = block[i] ^ lastBlockpreBlock[i];
		break;
	}
	return ret;
}

I_EXPORT int i_dec_init(I_CIPHER_CTX* p_context, const int p_cipher_id, uint8_t* p_key, uint32_t p_keylength, const EDGE_CIPHER_PARAMETERS* p_param) {
	if (p_context == NULL) {
		printf("i_dec_init() : 매개변수 오류\n");
		return -1;
	}

	memset(&(p_context->buffer), 0, 16);
	memset(&(p_context->lastDecBlock), 0, 16);
	p_context->cipher_id = p_cipher_id;
	p_context->param = *p_param;
	p_context->keylength = p_keylength;
	p_context->bufferSize = 0;
	p_context->total = 0;
	memcpy(p_context->key, p_key, p_keylength);

	return 0;
}

I_EXPORT int i_dec_update(I_CIPHER_CTX* p_context, uint8_t* p_input, uint32_t p_inputlength, uint8_t* p_output, uint32_t* p_outputlength) {
	int     ret = 0;

	uint8_t      block[16]; //plain_text xor pre_enc_data
	uint32_t     blocklength = 16; //block 길이
	uint32_t	 blockNum = 0;//q 성공할 때마다 증가하여 output의 인덱스를 올려줌
	uint32_t	 remainLength = 0;
	uint32_t	 index = 0;

	*p_outputlength = 0;//update시 p_outputlength는 0으로 초기화
	remainLength = p_inputlength;
	index = p_context->bufferSize;
	if (p_context->bufferSize != 0 || p_inputlength < blocklength) {//버퍼가 비어있지 않거나 input이 blocklength보다 작으면 버퍼부터 채운다.
		for (int i = index; i < blocklength; i++) {
			if (i - index == p_inputlength) break;
			p_context->buffer[i] = p_input[i - index];
			p_context->bufferSize++;
			remainLength--;
		}
	}
	p_context->total += p_inputlength;

	while (p_context->bufferSize == blocklength || remainLength >= 16) {//버퍼가 가득 찼을 경우
		switch (p_context->param.m_mode) {
		case EDGE_CIPHER_MODE_CBC:
			if (p_context->bufferSize == blocklength) {//우선 버퍼가 찼으면 버퍼부터 암호화
				ret = dec_ecb_to_cbc_pkcs5(p_context->cipher_id, p_context->key, p_context->keylength, p_context->buffer, blocklength, p_output + (blockNum * blocklength), p_outputlength, p_context->param.m_modeparam.m_iv, p_context->param.m_modeparam.m_ivlength);
				for (int i = 0; i < blocklength; i++)//버퍼에 이전 암호문을 iv에 저장
					p_context->param.m_modeparam.m_iv[i] = p_context->buffer[i];
			}
			else {
				ret = dec_ecb_to_cbc_pkcs5(p_context->cipher_id, p_context->key, p_context->keylength, p_input + (p_inputlength - remainLength), (remainLength / blocklength * blocklength), p_output + (blockNum * blocklength), p_outputlength, p_context->param.m_modeparam.m_iv, p_context->param.m_modeparam.m_ivlength);
				for (int i = 0; i < blocklength; i++)//이전 암호문 저장
					p_context->param.m_modeparam.m_iv[i] = p_input[i + (p_inputlength - remainLength) + (remainLength / blocklength * blocklength) - blocklength];
			}
			if (ret != 0) {
				print_result("i_dec_update", ret);
				return ret;
			}
			for (int i = 0; i < blocklength; i++)//마지막 복호문 저장
				p_context->lastDecBlock[i] = p_output[*p_outputlength - blocklength + i];
			break;
		case EDGE_CIPHER_MODE_CTR:
			if (p_context->bufferSize == blocklength)//우선 버퍼가 찼으면 버퍼부터 암호화
				ret = dec_ctr_mode(p_context->cipher_id, p_context->key, p_context->keylength, p_context->buffer, blocklength, p_output + (blockNum * blocklength), p_outputlength, p_context->param.m_modeparam.m_iv, p_context->param.m_modeparam.m_ivlength);
			else
				ret = dec_ctr_mode(p_context->cipher_id, p_context->key, p_context->keylength, p_input + (p_inputlength - remainLength), (remainLength / blocklength * blocklength), p_output + (blockNum * blocklength), p_outputlength, p_context->param.m_modeparam.m_iv, p_context->param.m_modeparam.m_ivlength);
			if (ret != 0) {
				print_result("i_dec_update", ret);
				return ret;
			}
			for (int i = 0; i < blocklength; i++)//마지막 복호문 저장
				p_context->lastDecBlock[i] = p_output[*p_outputlength - blocklength + i];
			break;
		}
		//남는 데이터 처리
		if (remainLength >= 16 && p_context->bufferSize == blocklength) {//buffer가 blocklength가 돼서 buffer를 먼저 암호화 한 경우
			p_context->bufferSize = 0;
			blockNum++;
			continue;
		}
		p_context->bufferSize = 0;
		remainLength %= blocklength;//최종 남은 데이터 길이
		for (int i = 0; i < remainLength; i++) {//버퍼에 남은 데이터 저장
			p_context->buffer[i] = p_input[p_inputlength - remainLength + i];
			p_context->bufferSize++;
		}
		blockNum++;
	}
	return ret;
}

I_EXPORT int i_dec_final(I_CIPHER_CTX* p_context, uint8_t* p_output, uint32_t* p_outputlength, uint32_t* p_paddingLength) {
	int ret = 0;
	if (p_context->total % 16 != 0) {
		printf("dec error\n");
		ret = -1;
		return ret;
	}
	if (p_output == NULL && p_outputlength == NULL) {
		*p_paddingLength = p_context->lastDecBlock[p_context->param.m_modeparam.m_modesize - 1];//패딩값 저장
		for (int i = 0; i < *p_paddingLength; i++) {
			if (p_context->lastDecBlock[p_context->param.m_modeparam.m_modesize - 1 - i] != *p_paddingLength) {//패딩 값에 대한 유효성 검증(마지막 복호문에서 패딩 검증)
				ret = -1;
				print_result("i_dec_final", ret);
				return ret;
			}
		}
		return ret;
	}
	else {
		printf("i_dec_final() : This funtion cannot dec stream Mode\n");
		return -1;
	}
}
