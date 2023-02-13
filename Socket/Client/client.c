#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include "i_symmetric.h"
#include "edge_crypto.h"

#define BUF_SIZE 100
#define NAME_SIZE 20

void* send_msg(void* arg);
void* recv_msg(void* arg);
void error_handling(char* message);

char name[NAME_SIZE] = "[DEFAULT]";
char msg[BUF_SIZE] = {0x00,};
//대칭암호에 필요한 값
uint8_t key[16] = {0x00, };
uint32_t keylength = 0;
uint32_t iv[16] = {0x00, };
uint8_t ivlength = 16;
int cipher_id = EDGE_CIPHER_ID_AES128;

EDGE_ASYM_ENC_PARAM asym_param;
EDGE_CIPHER_PARAMETERS cipher_param;

int main(int argc, char* argv[]){
	int sock;
	int ret = 0;
	struct sockaddr_in serv_addr;
	pthread_t send_thread, recv_thread;
	void* thread_return;

	EDGE_ASYM_KEY_PARAM key_param;
	uint8_t public_key[2048] = {0x00, };
	uint32_t public_keylength = 0;
	uint8_t private_key[2048] = {0x00, };
	uint32_t private_keylength = 0;
	uint8_t encKey[256];
	uint32_t encKeylength = 0;
	int msg_length = 0;

	ret = edge_crypto_init(NULL);
	if(ret!=0){
		print_result("edge_crypto_init", ret);
		return ret;
	}
	edge_crypto_change_mode();

	//init for symmetric	
	memset(&cipher_param, 0, sizeof(EDGE_CIPHER_PARAMETERS));
	cipher_param.m_padding = EDGE_CIPHER_PADDING_PKCS5;
	memcpy(cipher_param.m_modeparam.m_iv, iv, ivlength);
	cipher_param.m_modeparam.m_ivlength = ivlength;
	cipher_param.m_mode = EDGE_CIPHER_MODE_CBC;
	//init asym key
	memset(&key_param, 0, sizeof(EDGE_ASYM_KEY_PARAM));
	key_param.m_algorithm = EDGE_ASYM_ID_RSA;
	key_param.rsa.m_bits = 2048;
	key_param.rsa.m_exponent = 65537;
	
	//key 생성
	ret = edge_asym_gen_keypair(public_key, &public_keylength, private_key, &private_keylength, &key_param);
	if(ret != 0){
		printf("fail generate key pair %d\n", ret);
		return -1;
	}
	//key쌍 확인
	ret = edge_asym_verify_keypair(public_key, &public_keylength, private_key, &private_keylength, &key_param);
	if(ret != 0){
		printf("fail verify key pair %d\n", ret);
		return -1;
	}
	hexdump("public_key", public_key, public_keylength);
	
	//init for asymmetric
	asym_param.m_encMode = EDGE_RSA_ENC_MODE_OAEP;
	asym_param.m_oaep.m_hashAlg = EDGE_HASH_ID_SHA256;
	asym_param.m_oaep.m_label = NULL;
	asym_param.m_oaep.m_labelLength = 0;
	asym_param.m_oaep.m_mgfHashAlg = EDGE_HASH_ID_SHA256;

	if(argc != 4){//경로/ip/port/name
		printf("Usage : %s <IP> <port> <name> \n", argv[0]);
		exit(EXIT_FAILURE);
	}
	sprintf(name, "[%s]", argv[3]);
	sock = socket(PF_INET, SOCK_STREAM, 0);

	//init server info
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
	serv_addr.sin_port=htons(atoi(argv[2]));

	connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
	//연결에 성공하면 서버에 공개키의 길이와 공개키를 보냄
	send(sock, public_key, public_keylength, 0);
	//자신이 보낸 공개키로 암호화된 대칭키를 서버로부터 획득
	encKeylength = recv(sock, encKey, 256, 0);
	hexdump("encKey", encKey, encKeylength);
	//암호화된 대칭키를 자신의 개인키로 복호화하여 최종적으로 대칭키 획득
	ret = edge_asym_dec(private_key, private_keylength, &asym_param, encKey, encKeylength, key, &keylength);
	if(ret!=0){
		printf("fail dec\n");
		return ret;
	}
	hexdump("key", key, keylength);

	pthread_create(&send_thread, NULL, send_msg, (void*)&sock);
	pthread_create(&recv_thread, NULL, recv_msg, (void*)&sock);

	pthread_join(send_thread, &thread_return);
	pthread_join(recv_thread, &thread_return);
	close(sock);

	edge_crypto_final();
	
	return 0;
}

void* send_msg(void* arg){//전체 메시지를 암호화해서 서버에 전송
	int sock = *((int*)arg);
	char name_msg[NAME_SIZE + BUF_SIZE] ={0x00, };//buffer for sending message with name

	uint8_t encData[256] = {0x00, };
	uint32_t encDataLength = 0;

	//처음 연결 성고하면 연결 메시지 보냄
	sprintf(name_msg, "%s %s", name, "Connected...\n");
	i_enc(cipher_id, key, keylength, &cipher_param, name_msg, strlen(name_msg), encData, &encDataLength);
	write(sock, encData, encDataLength);//크기를 보낸 후 메세지를 보냄
	
	while(1){
		memset(msg, 0, BUF_SIZE);
		memset(name_msg, 0, NAME_SIZE+BUF_SIZE);
		memset(encData, 0, 256);
		encDataLength = 0;
		printf("-> ");
		fgets(msg, BUF_SIZE, stdin);
		//q or Q를 입력받으면 클로즈 메시지 보내고 소켓 종료
		if(!strcmp(msg, "q\n") || !strcmp(msg, "Q\n")){
			sprintf(name_msg, "%s %s", name, "Closed...\n");
			i_enc(cipher_id, key, keylength, &cipher_param, name_msg, strlen(name_msg), encData, &encDataLength);
			write(sock, encData, encDataLength);
			close(sock);
			exit(EXIT_SUCCESS);
		}
		sprintf(name_msg, "%s %s", name, msg);
		i_enc(cipher_id, key, keylength, &cipher_param, name_msg, strlen(name_msg), encData, &encDataLength);
		write(sock, encData, encDataLength);
	}

	return NULL;
}

void* recv_msg(void* arg){//서버로부터 받은 다른 클라이언트의 메시지를 복호화하여 콘솔에 출력
	int sock = *((int*)arg);
	char name_msg[NAME_SIZE+BUF_SIZE] = {0x00,};
	int str_len = 0;
	uint8_t decData[256] = {0x00,};
	uint32_t decDataLength = 0;

	while(1){
		str_len = read(sock, name_msg, NAME_SIZE+BUF_SIZE-1);
		//name_msg[str_len] = '\0';
		i_dec(cipher_id, key, keylength, &cipher_param, name_msg, str_len, decData, &decDataLength);
		decData[decDataLength] = '\0';
		fputs(decData, stdout);
		memset(name_msg, 0, NAME_SIZE+BUF_SIZE);
		memset(decData, 0, decDataLength);
		decDataLength = 0;
		str_len = 0;
	}

	return NULL;
}

void error_handling(char* message){
	fputs(message, stderr);
	fputc('\n', stderr);
	exit(EXIT_FAILURE);
}
