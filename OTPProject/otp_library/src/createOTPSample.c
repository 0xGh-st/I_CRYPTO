#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "otp.h"

int createOTPSample(){
	srand(time(NULL));//To generate random number for serial number card 
	int ret = 0;

	char serialNum[6] = {0x00};
	unsigned int serialNumLength = 6;
	char key[32] = {0x00, };
	unsigned int keyLength = 32;
	unsigned int otpDigit = 0;
	unsigned int lifeTime = 0;
	unsigned int mode = 0;
	unsigned int EXTRACT_START_INDEX = 0;
	unsigned int EXTRACT_SIZE = 0;
	char buf[128] = {0x00, };

	FILE *Settings = fopen("dir of settings.txt", "r");
	if(Settings == NULL){
		return -1;
	}

	FILE *SerialNumberCardDIR = fopen("dir of serialnumbercard.txt", "w");
	if(SerialNumberCardDIR == NULL){
		fclose(Settings);
		return -1;
	}
	FILE *otpHD = fopen("dir of otp machine/otpHD.txt", "w");
	if(otpHD == NULL){
		fclose(Settings);
		fclose(SerialNumberCardDIR);
		return -1;
	}
	FILE *ServerDBDIR = fopen("dir of ServerDB.txt", "w");
	if(ServerDBDIR == NULL){
		fclose(Settings);
		fclose(SerialNumberCardDIR);
		fclose(otpHD);
		return -1;
	}
	
	//세팅 파일에서 데이터 파싱 예시
	while(!feof(Settings)){
		fgets(buf, 128, Settings);
		if(strstr(buf, "keyLength") != NULL){
			strtok(buf, " ");
			keyLength = atoi(strtok(NULL, " "));
		}
		else if(strstr(buf, "serialNumLength") != NULL){
			strtok(buf, " ");
			serialNumLength = atoi(strtok(NULL, " "));
		}
		else if(strstr(buf, "otpDigit") != NULL){
			strtok(buf, " ");
			otpDigit = atoi(strtok(NULL, " "));
		}
		else if(strstr(buf, "lifeTime") != NULL){
			strtok(buf, " ");
			lifeTime = atoi(strtok(NULL, " "));
		}
		else if(strstr(buf, "mode") != NULL){
			strtok(buf, " ");
			mode = atoi(strtok(NULL, " "));
		}
		else if(strstr(buf, "EXTRACT_SIZE") != NULL){
			strtok(buf, " ");
			EXTRACT_SIZE = atoi(strtok(NULL, " "));
		}
		else if(strstr(buf, "EXTRACT_START_INDEX") != NULL){
			strtok(buf, " ");
			EXTRACT_START_INDEX = atoi(strtok(NULL, " "));
			break;
		}
	}

	//if you want to use otp_library, you have to call otp_init();
	otp_init();

	//for making otp machine, you need serial number and key
	set_serial_number(serialNum, serialNumLength);
	//set_key(key, keyLength);
	
	//시리얼 넘버 카드에 시리얼 넘버를 씀
	ret = write_serial_number(SerialNumberCardDIR, serialNum, serialNumLength);
	if(ret!=0){
		printf("write_serial_number() %d\n", ret);
		fclose(SerialNumberCardDIR);
		fclose(otpHD);
		fclose(ServerDBDIR);
		fclose(Settings);
		return ret;
	}
	//write key to otp machine's harddisk
	ret = write_otpHD(otpHD, key, keyLength, lifeTime, otpDigit, mode, EXTRACT_START_INDEX, EXTRACT_SIZE);
	if(ret!=0){
		printf("write_otpHard %d\n", ret);
		fclose(SerialNumberCardDIR);
		fclose(otpHD);
		fclose(ServerDBDIR);
		fclose(Settings);
		return ret;
	}
	//write key to serialNumber in ServerDB
	ret = write_serverDB(ServerDBDIR, serialNum, serialNumLength, key, keyLength, otpDigit, lifeTime, mode, EXTRACT_START_INDEX, EXTRACT_SIZE);
	if(ret!=0){
		printf("write_serverDB %d\n", ret);
		fclose(SerialNumberCardDIR);
		fclose(otpHD);
		fclose(ServerDBDIR);
		fclose(Settings);
		return ret;
	}

	fclose(SerialNumberCardDIR);
	fclose(otpHD);
	fclose(ServerDBDIR);
	fclose(Settings);
	

	//if you called otp_init(), In the end, you have to call otp_final()
	otp_fianl();
}
