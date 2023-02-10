#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include "otp.h"

int main(){
	int ret = 0;
	char input[32] = {0x00, };
	unsigned int inputOTP = 0;
	time_t currentTime = 0;

	unsigned int validTime = 0;
	char serialNum[16] = {0x00};
	char key[64] = {0x00, };
	unsigned int keyLength = 0;
	unsigned otpDigit = 0;
	unsigned int lifeTime = 0;
	unsigned int mode = 0;
	unsigned int EXTRACT_START_INDEX = 0;
	unsigned int EXTRACT_SIZE = 0;
	unsigned int offset = 0;
	char buf[32] = {0x00};

	FILE* fp = fopen("ServerDB.txt", "r");
	if(fp == NULL){
		printf("파일 오픈 에러\n");
		return -1;
	}

	//서버가 운영할 유효시간 가져옴
	while(!feof(fp)){
		fgets(buf, 32, fp);
		if(strstr(buf, "validTime") != NULL){
			strtok(buf, " ");
			validTime = atoi(strtok(NULL, " "));
		}
	}
	rewind(fp);
	
	ret = otp_init();
	if(ret != 0){
		printf("edge_crypto_init %d\n", ret);
		return ret;
	}

	//시리얼번호를 이용해 otp기계의 정보를 가져옴
	ret = -1;
	int count = 0;
	while(ret != 0){
		printf("시리얼 번호 입력 : ");
		gets(serialNum);
		ret = read_OTP_info(fp, serialNum, strlen(serialNum), key, &keyLength, &otpDigit, &lifeTime, &mode, &EXTRACT_START_INDEX, &EXTRACT_SIZE, &offset);
		if(ret == -1){
			printf("없는 시리얼 번호입니다. 다시 입력하세요.\n");
			rewind(fp);
			count++;
		}
		if(count == 3){
			printf("횟수 초과!!\n");
			fclose(fp);
			return 0;
		}
	}
	fclose(fp);
	
	//정보를 읽어오면 반드시 validator로 값들의 유효성을 검증해야 한다.
	ret = otp_option_validator(strlen(serialNum), keyLength, otpDigit, lifeTime, mode, EXTRACT_START_INDEX, EXTRACT_SIZE);
	if(ret != 0) return ret;

	ret = -1;
	count = 0;

	//otp 검증
	while(ret != 0){
		printf("otp 번호 입력 : ");
		gets(input);
		printf("\n");
		inputOTP = atoi(input);
		
		if(count==3){
			printf("횟수 초과!!\n");
			otp_final();
			return 0;
		}

		if(inputOTP == 0){
			printf("OTP 인증 실패!!\n");
			count++;
			continue;
		}

		ret = verifyOTP(inputOTP, validTime, key, keyLength, otpDigit, lifeTime, mode, EXTRACT_START_INDEX, EXTRACT_SIZE, offset);

		if(ret == -1){
			printf("OTP 인증 실패!!\n");
			count++;
		}
		if(ret == -2 || ret == -3) return ret;
	}
	printf("OTP 인증 성공!!\n");

	otp_final();

	return ret;
}
