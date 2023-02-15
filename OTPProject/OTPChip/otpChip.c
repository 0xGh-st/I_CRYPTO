#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include "otp.h"

int main(){
	int ret = 0;

	unsigned int otp = 0;
	//otp를 생성하기 위한 시간 정보 저장
	//LIFE_TIME_OF_OTP만큼의 시간이 흐르지 않으면 값을 바꾸지 않아 유효시간을 보장
	time_t valid_time = 0;
	//현재시간을 계속 가져오는 변수
	time_t currentTime = 0;
	
	char otpHD[256] = {0x00, };
	char* keyLengthBuf;
	char* key = NULL;
	unsigned int keyLength = 0;
	unsigned int otpDigit = 0;
	unsigned int lifeTime = 0;
	unsigned int mode = 0;
	unsigned int EXTRACT_START_INDEX = 0;
	unsigned int EXTRACT_SIZE = 0;
	
	char tmp[16] = {0x00, };
	char result[16] = {0x00, };

	FILE* fp = fopen("otpHD.txt", "r");
	if(fp == NULL){
		printf("디스크를 읽을 수 없음\n");
		return -1;
	}
	//데이터 파싱
	fread(otpHD, 1, 256, fp);
	keyLengthBuf = strtok(otpHD, "||");
	keyLength = atoi(keyLengthBuf);
	key = otpHD + strlen(keyLengthBuf) + 2;
	otpDigit = atoi(strtok(otpHD + strlen(keyLengthBuf) + 2 + keyLength + 2, "||"));
	lifeTime = atoi(strtok(NULL, "||"));
	mode = atoi(strtok(NULL, "||"));
	EXTRACT_START_INDEX = atoi(strtok(NULL, "||"));
	EXTRACT_SIZE = atoi(strtok(NULL, "||"));
	fclose(fp);

	time(&valid_time);

	while(1){
		currentTime = 0;;
		time(&currentTime);

		//otp가 generate될 때 무조건 lifeTime만큼 otp가 살이있게 하기 위해
		if(valid_time+lifeTime<=currentTime)
			valid_time = currentTime;	

		otp = generateOTP(valid_time, key, keyLength, otpDigit, lifeTime, mode, EXTRACT_START_INDEX, EXTRACT_SIZE);
		if(otp == -1){
			printf("OTP 생성 실패\n");
			return otp;
		}

		memset(tmp, 0 ,16);
		memset(result, 0, 16);
		//printf("second : %ld\n", currentTime - valid_time);
		//출력 자릿수 맞춤
		sprintf(tmp, "%d", otp);
		if(strlen(tmp) < otpDigit)
			for(int i=0;i<otpDigit-strlen(tmp);i++)
				strcat(result, "0");	
		strcat(result, tmp);
		printf("%s : %02ld\r", result, currentTime - valid_time);
		fflush(stdout);
		sleep(1);
	}
}
