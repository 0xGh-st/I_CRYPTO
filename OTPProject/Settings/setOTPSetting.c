#include <stdio.h>
#include <stdlib.h>

int main(){
	int ret = 0;
	
	unsigned int lifeTime = 0;
	unsigned int mode = 0;
	unsigned int otpDigit = 0;
	unsigned int serialNumDigit = 0;
	unsigned int keyLength = 0;
	unsigned int EXTRACT_START_INDEX = 0;
	unsigned int EXTRACT_SIZE = 0;

	FILE *settings = fopen("settings.txt", "w");

	ret = -1;
	while(ret != 0){
		printf("serialNumDigit : ");
		scanf("%d", &serialNumDigit);
		if(serialNumDigit <= 0){
			printf("please intput valid serialNum length\n");
			continue;
		}

		printf("keyLength : ");
		scanf("%d", &keyLength);
		if(keyLength <= 0){
			printf("please intput valid ketLength\n");
			continue;
		}

		printf("otpDigit : ");
		scanf("%d", &otpDigit);
		if(otpDigit <= 0){
			printf("please intput valid otp digit\n");
			continue;
		}

		printf("lifeTime : ");
		scanf("%d", &lifeTime);
		if(lifeTime <= 0){
			printf("please intput valid life time\n");
			continue;
		}

		printf("mode(1->static, 2->Dynamic) : ");
		scanf("%d", &mode);
		if(mode != 1 && mode != 2){
			printf("please intput valid mode\n");
			continue;
		}
	
		printf("EXTRACT_SIZE : ");
		scanf("%d", &EXTRACT_SIZE);
		if(EXTRACT_SIZE <= 0){
			printf("please intput valid EXTRACT_SIZE\n");
			continue;
		}

		printf("EXTRACT_START_INDEX : ");
		scanf("%d", &EXTRACT_START_INDEX);
		if(EXTRACT_START_INDEX < 0 || EXTRACT_START_INDEX > keyLength - EXTRACT_SIZE){
			printf("please intput valid EXTRACT_START_INDEX\n");
			continue;
		}
		ret = 0;
	}

	fprintf(settings, "serialNumDigit %d\n", serialNumDigit);
	fprintf(settings, "keyLength %d\n", keyLength);
	fprintf(settings, "otpDigit %d\n", otpDigit);
	fprintf(settings, "lifeTime %d\n", lifeTime);
	fprintf(settings, "mode %d\n", mode);
	fprintf(settings, "EXTRACT_SIZE %d\n", EXTRACT_SIZE);
	fprintf(settings, "EXTRACT_START_INDEX %d\n", EXTRACT_START_INDEX);
	
	fclose(settings);
}
