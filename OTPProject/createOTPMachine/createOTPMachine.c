#include <stdio.h>
#include <stdlib.h>
#include "otp.h"
#include <time.h>
#include <string.h>

int main(){
	srand(time(NULL));

	int ret = 0;

    char key[16] = {'a', 'b', 'c', 'd',
                    'e', 'f', 'g', 'h',
                    'i', 'j', 'k', 'l',
                    'm', 'n', 'o', 'p'};
	unsigned int keyLength = 0;
	char serialNum[16] = {0x00, };
	unsigned int serialNumDigit = 0;
	unsigned int otpDigit = 0;
	unsigned int lifeTime = 0;
	unsigned int mode = 0;
	unsigned int EXTRACT_START_INDEX = 0;
	unsigned int EXTRACT_SIZE = 0;
	char OTPMachineName[32] = {0x00, };
	char OTPMachineDIR[64] = "../";
	char serialFile[64] = {0x00, };
	char otphardFile[64] = {0x00, };
	char buf[128] = {0x00, };
	char syscallMsg[128] = "cp ";
	//for customer
	FILE *serialNumCard = NULL;//고객이 보관하는 시리얼넘버 카드
	FILE *otpHD = NULL;//otp machine의 하드디스크

	//for Server
	//서버는 otp기계의 시리얼 넘버, 키, 모드, offset의 정보를 갖고 있다.
	FILE *serverDB = NULL;
	//open settings.txt
	FILE *settings = fopen("../Settings/settings.txt", "r");
	if(settings == NULL ){
		printf("file open error\n");
		return -1;
	}

	//settings에서 otp 생성에 필요한 정보들을 가져옴
	ret = read_settings(settings, &serialNumDigit, &keyLength, &otpDigit, &lifeTime, &mode, &EXTRACT_START_INDEX, &EXTRACT_SIZE);
	fclose(settings);
	if(ret != 0) return ret;

	//set_key(key, keyLength);
	set_serial_number(serialNum, serialNumDigit);
	
	//값 검증
	ret = otp_option_validator(serialNumDigit, keyLength, otpDigit, lifeTime, mode, EXTRACT_START_INDEX, EXTRACT_SIZE);
	if(ret != 0) return ret;

	//OTPMachine 생성에 필요한 기기 이름과 경로 설정
	printf("input OTPMachine's Name : ");
	gets(OTPMachineName);
	strcat(OTPMachineDIR, OTPMachineName);
	strcat(OTPMachineDIR, "/");
	strcat(otphardFile, OTPMachineDIR);
	strcat(otphardFile, "otpHD.txt");
	strcat(serialFile, OTPMachineDIR);
	strcat(serialFile, "serialNumberCard.txt");

	//write serialNumber to customer's serial card
	serialNumCard = fopen(serialFile, "w");
	if(serialNumCard == NULL ){
		printf("file open error\n");
		return -1;
	}
	ret = write_serial_number(serialNumCard, serialNum, serialNumDigit);
	fclose(serialNumCard);
	if(ret!=0){
		printf("write_serial_number() %d\n", ret);
		return ret;
	}

	//write key to otp machine's harddisk
	otpHD = fopen(otphardFile, "w");
	if(otpHD == NULL ){
		printf("file open error\n");
		return -1;
	}
	ret = write_otpHD(otpHD, key, keyLength, otpDigit, lifeTime, mode, EXTRACT_START_INDEX, EXTRACT_SIZE);
	fclose(otpHD);
	if(ret!=0){
		printf("write_otpHD %d\n", ret);
		return ret;
	}

	//write key to serialNumber in ServerDB
	serverDB = fopen("../Bank/ServerDB.txt", "a");
	if(serverDB == NULL ){
		printf("file open error\n");
		return -1;
	}
	ret = write_serverDB(serverDB, serialNum, serialNumDigit, key, keyLength, otpDigit, lifeTime, mode, EXTRACT_START_INDEX, EXTRACT_SIZE);
	fclose(serverDB);
	if(ret!=0){
		printf("write_serverDB %d\n", ret);
		return ret;
	}

	//insert otp chip in otp machine
	strcat(syscallMsg, "../OTPChip/otpChip ");
	strcat(syscallMsg, OTPMachineDIR);
	ret = system(syscallMsg);
	if(ret != 0){
		printf("syscall failed\n");
		return ret;
	}

	printf("CREATE OTP SUCCESS!!\n");
}
