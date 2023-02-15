#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include "otp.h"

int validatorFlag = 0;

//validator
int otp_option_validator(const unsigned int serialNumDigit, const unsigned int keyLength,
						 const unsigned int otpDigit, const unsigned int lifeTime,
						 const unsigned int mode, const unsigned int EXTRACT_START_INDEX,
						 const unsigned int EXTRACT_SIZE){
	if(serialNumDigit < MIN_DIGIT || serialNumDigit > MAX_DIGIT){
		printf("validator() invalid serialNumDigit\n");
		validatorFlag = -1;
		return -1;
	}
	if(keyLength < MIN_KEY_LENGTH || keyLength > MAX_KEY_LENGTH){
		printf("validator() invalid keyLength\n");
		validatorFlag = -1;
		return -1;
	}
	if(otpDigit < MIN_DIGIT || otpDigit > MAX_DIGIT){
		printf("validator() invalid otpDigit\n");
		validatorFlag = -1;
		return -1;
	}
	if(lifeTime < MIN_LIFE_TIME || lifeTime > MAX_LIFE_TIME){
		printf("validator() invalid lifeTIme\n");
		validatorFlag = -1;
		return -1;
	}
	if(mode != STATIC_MODE && mode != DYNAMIC_MODE){
		printf("validator() invalid mode\n");
		validatorFlag = -1;
		return -1;
	}
	if(EXTRACT_START_INDEX < 0){
		printf("validator() invalid EXTRACT_START_INDEX\n");
		validatorFlag = -1;
		return -1;
	}

	validatorFlag = 1;

	return 0;
}

//serial number and key generate
void set_serial_number(char* serialNum, uint32_t serialNumDigit){
	for(int i=0; i<serialNumDigit; i++)
		serialNum[i] = rand() % 10 + '0';
}

//write
int write_serial_number(FILE* const fp, const char* const serialNum, const uint32_t serialNumDigit){
	if(fp == NULL || serialNum == NULL){
		printf("write_serial_number() : 매개변수 오류\n");
		return -1;
	}
	if(validatorFlag == 0){
		printf("write_serial_number() : 값 검증이 이루어지지 않았습니다.\n");
		return -2;
	}
	if(validatorFlag == -1){
		printf("write_serial_number() : otp option 값 중에 유효하지 않은 값이 있습니다.\n");
		return -3;
	}
	fprintf(fp, "serialNum ");
	for(int i=0;i<serialNumDigit;i++)
		fputc(serialNum[i], fp);
	fputc('\n', fp);
	return 0;
}

int write_otpHD(FILE* const fp, 
				const char* const key, const unsigned int keyLength, 
				const unsigned int otpDigit, const unsigned int lifeTime, 
				const unsigned int mode, const unsigned int EXTRACT_START_INDEX, 
				const unsigned int EXTRACT_SIZE){
	if(fp == NULL){
		printf("write_otpHD() : 매개변수 에러\n");
		return -1;
	}
	if(validatorFlag == 0){
		printf("write_otpHD() : 값 검증이 이루어지지 않았습니다.\n");
		return -2;
	}
	if(validatorFlag == -1){
		printf("write_HD() : otp option 값 중에 유효하지 않은 값이 있습니다.\n");
		return -3;
	}
	fprintf(fp, "%d||", keyLength);
	for(int i=0;i<keyLength;i++)
		fputc(key[i], fp);
	fprintf(fp, "||%d||%d||%d||%d||%d\n", otpDigit, lifeTime, mode, EXTRACT_START_INDEX, EXTRACT_SIZE);
	return 0;
}

int write_serverDB(FILE* const fp,
				   const char* const serialNum, const uint32_t serialNumDigit, 
				   const char* const key, const unsigned int keyLength, 
				   const unsigned int otpDigit, const unsigned int lifeTime, 
				   const unsigned int mode, const unsigned int EXTRACT_START_INDEX, 
				   const unsigned int EXTRACT_SIZE){
	if(fp == NULL){
		printf("wirte_serverDB() : 매개변수 에러\n");
		return -1;
	}
	if(validatorFlag == 0){
		printf("write_serverDB() : 값 검증이 이루어지지 않았습니다.\n");
		return -2;
	}
	if(validatorFlag == -1){
		printf("write_serverDB() : otp option 값 중에 유효하지 않은 값이 있습니다.\n");
		return -3;
	}
	//처음 otp정보를 저장할 때 보정값 offset은 0으로 설정

	for(int i=0;i<serialNumDigit;i++)
		fputc(serialNum[i], fp);
	fprintf(fp, "||%d||", keyLength);
	for(int i=0;i<keyLength;i++)
		fputc(key[i], fp);
	fprintf(fp, "||%d||%d||%d||%d||%d||%d\n\n\n", otpDigit, lifeTime, mode, EXTRACT_START_INDEX, EXTRACT_SIZE, 0);
	return 0;
}

//read
int read_settings(FILE* const fp,
				  unsigned int* serialNumDigit, unsigned int* keyLength, 
				  unsigned int* otpDigit, unsigned int* lifeTime, 
				  unsigned int* mode, unsigned int* EXTRACT_START_INDEX, 
				  unsigned int* EXTRACT_SIZE){
	char buf[128] = {0x00, };

	if(fp == NULL){
		printf("read_settings() 매개변수 오류 file이 유효하지 않습니다.\n");
		return -1;
	}

	while(!feof(fp)){
		fgets(buf, 128, fp);
		if(strstr(buf, "serialNumDigit") != NULL){
			strtok(buf, " ");
			*serialNumDigit = atoi(strtok(NULL, " "));
		}
		else if(strstr(buf, "keyLength") != NULL){
			strtok(buf, " ");
			*keyLength = atoi(strtok(NULL, " "));
		}
		else if(strstr(buf, "otpDigit") != NULL){
			strtok(buf, " ");
			*otpDigit = atoi(strtok(NULL, " "));
		}
		else if(strstr(buf, "lifeTime") != NULL){
			strtok(buf, " ");
			*lifeTime = atoi(strtok(NULL, " "));
		}
		else if(strstr(buf, "mode") != NULL){
			strtok(buf, " ");
			*mode = atoi(strtok(NULL, " "));
		}
		else if(strstr(buf, "EXTRACT_SIZE") != NULL){
			strtok(buf, " ");
			*EXTRACT_SIZE = atoi(strtok(NULL, " "));
		}
		else if(strstr(buf, "EXTRACT_START_INDEX") != NULL){
			strtok(buf, " ");
			*EXTRACT_START_INDEX = atoi(strtok(NULL, " "));
			break;
		}
	}
	return 0;
}


int read_OTP_info(FILE* const fp,
				  char* serialNum, uint32_t serialNumDigit, 
				  char* key, uint32_t* keyLength, 
				  uint32_t* otpDigit, uint32_t* lifeTime, 
				  uint32_t* mode, uint32_t* EXTRACT_START_INDEX, 
				  uint32_t* EXTRACT_SIZE, uint32_t* offset){
	int ret = -1;
	
	uint8_t* keyLengthBuf = NULL;
	uint8_t buf[128] = {0x00, };
	uint8_t otpInfoBuf[128] = {0x00, };
	uint32_t bufSize = 128;

	//serial 번호를 이용해 해당 otp기계의 정보를 구함
	while(!feof(fp)){
		int cursor = ftell(fp);
		fgets(buf, bufSize, fp);
		if(strstr(buf, serialNum) != NULL){
			fseek(fp, cursor, SEEK_SET);
			fread(otpInfoBuf, 1, bufSize, fp);
			ret = 0;
			break;
		}
	}
	
	if(ret != 0) return -1;
	if(strlen(strtok(otpInfoBuf, "||")) != serialNumDigit) return -1;

	keyLengthBuf = strtok(NULL, "||");
	*keyLength = atoi(keyLengthBuf);
	for(int i=0;i<*keyLength;i++)
		key[i] = (otpInfoBuf+serialNumDigit+2+strlen(keyLengthBuf)+2)[i];//2 -> ||

	*otpDigit = atoi(strtok(otpInfoBuf + serialNumDigit + 2 + strlen(keyLengthBuf) + 2 + *keyLength + 2, "||"));
	*lifeTime = atoi(strtok(NULL, "||"));
	*mode = atoi(strtok(NULL, "||"));
	*EXTRACT_START_INDEX = atoi(strtok(NULL, "||"));
	*EXTRACT_SIZE = atoi(strtok(NULL, "||"));
	*offset = atoi(strtok(NULL, "||"));
	
	return 0;
}

uint32_t generateOTP(time_t currentTime, char* key, 
					 uint32_t keyLength, uint32_t otpDigit, 
					 uint32_t lifeTime, uint32_t mode, 
					 uint32_t EXTRACT_START_INDEX, uint32_t EXTRACT_SIZE){	
	int ret = 0;

	//int mac_id = EDGE_HMAC_ID_SHA256;
	AES_KEY hmacKey;
	uint8_t output[1024] = {0x00, };
	uint32_t outputlength = 0;
	uint32_t timer = 0;
	struct tm* t;

	t = localtime(&currentTime);
		
	currentTime += (t->tm_sec/lifeTime * lifeTime) - t->tm_sec;
	

	if(AES_set_encrypt_key(key, 256, &(hmacKey)) < 0){
		printf("i_enc_init() key 생성 오류\n");
		return 0;
	}
	HMAC(EVP_sha256(), &hmacKey, keyLength, (uint8_t*)&currentTime, sizeof(currentTime), output, &outputlength);
	// ret = edge_mac(mac_id, key, keyLength, (uint8_t*)&currentTime, sizeof(currentTime), output, &outputlength);
	// if(ret != 0){
	// 	printf("edge_mac %d\n", ret);
	// 	return 0;
	// }
		
	uint32_t OTP = 0;
	if(mode == 2)//Dynamic mode, output의 마지막 값에 하위 4비트를 시작 인덱스로 사용.
		EXTRACT_START_INDEX = output[outputlength-1] & 0x0f;
	for(int i=EXTRACT_START_INDEX;i<EXTRACT_START_INDEX+EXTRACT_SIZE;i++)
		OTP += (output[i] << i*8); //little endian
		
	OTP %= (uint32_t)pow(10, otpDigit);
	
	return OTP;
}

int verifyOTP(uint32_t input, uint32_t validTime, 
			  char* key, uint32_t keyLength, 
			  uint32_t otpDigit, uint32_t lifeTime, 
			  uint32_t mode, uint32_t EXTRACT_START_INDEX, 
			  uint32_t EXTRACT_SIZE, uint32_t offset){
	if(validatorFlag == 0){
		printf("verifyOTP() : 값 검증이 이루어지지 않았습니다.\n");
		return -2;
	}
	if(validatorFlag == -1){
		printf("verifyOTP() : otp option 값 중에 유효하지 않은 값이 있습니다.\n");
		return -3;
	}
	
	int i = 0;
	int step = 0;
	uint32_t otp = 0;
	time_t currentTime = 0;
	time(&currentTime);
	currentTime += offset;// offset값으로 otp와 서버 시간 맞춤

	//ex validTime  = 60, lifeTime = 30 -> step = 2, || validTime = 40, lifeTime = 30 -> step = 2. 즉 validTime이 lifeTime의 정 배수가 아니면 유효시간 보장을 위해 + 1
	if(validTime % lifeTime == 0) step = validTime / lifeTime;
	else step = validTime / lifeTime + 1;

	//ex step이 2일 때, -2 -1 0 1 2 순으로 반복
	i -= step;
	while(i<step+1){
		otp = generateOTP((currentTime + (i*(int)lifeTime)), key, keyLength, otpDigit, lifeTime, mode, EXTRACT_START_INDEX, EXTRACT_SIZE);
		if(otp == 0) return -1;
		if(input == otp)
			return 0;
		i++;
	}
	return -1;
}
