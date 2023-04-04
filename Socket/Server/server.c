#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include "i_crypto.h"

#define BUF_SIZE 256
#define MAX_CLNT 256

void* handle_clnt(void* arg);
void send_msg(int clnt_sock, char* msg, int len);
int recv_all(int msg_length, int sock, uint8_t* buf);
int read_all(int msg_length, int sock, uint8_t* buf);
void error_handling(char* message);

int clnt_cnt = 0;
int clnt_socks[MAX_CLNT];
pthread_mutex_t mutx;

int main(int argc, char* argv[]){
	int serv_sock, clnt_sock;
	struct sockaddr_in serv_addr, clnt_addr;
	socklen_t clnt_addr_size;
	pthread_t t_id;
	int ret = 0;

	int cipher_id = I_CIPHER_ID_AES128;
	uint8_t key[16] = {0x01, 0x02, 0x03, 0x04,
					   0x05, 0x06, 0x07, 0x08,
					   0x09, 0x0a, 0x0b, 0x0c,
					   0x0d, 0x0e, 0x0f, 0x10};
	uint32_t keylength = 16;
	uint8_t encKey[256] = {0x00,};
	uint32_t encKeylength = 0;

	uint8_t client_public_key[2048] = {0x00,};
	uint32_t client_public_keylength = 0;

	if(argc!=2){//경로/port번호 입력받아야함
		printf("Usage : %s <port> \n", argv[0]);
		exit(EXIT_FAILURE);
	}

	pthread_mutex_init(&mutx, NULL);//mutex생성

	serv_sock = socket(PF_INET, SOCK_STREAM, 0); //소켓 생성

	//init server
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(atoi(argv[1]));
	
	//소켓에 주소할당
	bind(serv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
	//listen
	listen(serv_sock, 5);

	while(1){
		int msg_length = 0;
		
		//accept client, and create new socket
		clnt_addr_size = sizeof(clnt_addr);
		clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_addr, &clnt_addr_size);
		printf("Connected IP : %s\n", inet_ntoa(clnt_addr.sin_addr));
		
		//클라이언트의 공개키를 받음
		recv(clnt_sock, &msg_length, sizeof(msg_length), 0);
		msg_length = ntohl(msg_length);
		client_public_keylength = recv_all(msg_length, clnt_sock, client_public_key);
		if(msg_length != client_public_keylength || client_public_keylength == -1){
			printf("main error, client_public_keylength : %d, msg_length : %d\n", client_public_keylength, msg_length);
			close(clnt_sock);
			return -1;
		}
		hexdump("client_public_key", client_public_key, client_public_keylength);
		
		//클라이언트의 공개키로 대칭키를 암호화
		ret = public_encrypt(key, keylength, client_public_key, encKey);
		if(ret == -1){
			printf("rsa enc failed...\n");
			close(clnt_sock);
			return ret;
		}
		encKeylength = ret;
		
		//I_asym_enc(client_public_key, client_public_keylength, &param, key, keylength, encKey, &encKeylength);  
		hexdump("key", key, keylength);
		hexdump("encKey", encKey, encKeylength);
		
		//암호화한 대칭키 전송
		msg_length = 0;
		msg_length = htonl(encKeylength);
		send(clnt_sock, &msg_length, sizeof(msg_length), 0);
		send(clnt_sock, encKey, encKeylength, 0);

		//실제 대칭키의 크기를 클라이언트에게 전송
		msg_length = 0;
		msg_length = htonl(keylength);
		send(clnt_sock, &msg_length, sizeof(msg_length), 0);

		//client 갯수 증가(mutex처리)
		pthread_mutex_lock(&mutx);
		clnt_socks[clnt_cnt++] = clnt_sock;	
		pthread_mutex_unlock(&mutx);

		//create Thread...
		pthread_create(&t_id, NULL, handle_clnt, (void*)&clnt_sock);
		pthread_detach(t_id);
	}
	return 0;
}
//전송 받을 메시지의 크기를 먼저 받았을 때 그 크기만큼 데이터를 읽는 함수(recv함수가 한번에 모든 데이터를 다 안읽어왔을수도 있기 때문)
int recv_all(int msg_length, int sock, uint8_t* buf){
    int ret = 0;

    // fd_set 구조체 초기화
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds);

    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    while (ret != msg_length) {
        // select 함수 호출
        int ready = select(sock + 1, &read_fds, NULL, NULL, &timeout);
        if (ready < 0) {
            return -1;
        } else if (ready == 0) {
            // 타임아웃 발생
            return -1;
        } else {
            ret += recv(sock, buf+ret, msg_length-ret, 0);
        }
    }
    return ret;
}
//전송 받을 메시지의 크기를 먼저 받았을 때 그 크기만큼 데이터를 읽는 함수(read함수가 한번에 모든 데이터를 다 안읽어왔을수도 있기 때문)
int read_all(int msg_length, int sock, uint8_t* buf){
    int ret = 0;

    // fd_set 구조체 초기화
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds);

    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    while (ret != msg_length) {
        // select 함수 호출
        int ready = select(sock + 1, &read_fds, NULL, NULL, &timeout);
        if (ready < 0) {
            return -1;
        } else if (ready == 0) {
            // 타임아웃 발생
            return -1;
        } else {
            ret += read(sock, buf+ret, msg_length-ret);
        }
    }
    return ret;
}

void* handle_clnt(void* arg){
	int clnt_sock = *((int*)arg); //파일 디스크립터
	int str_len = 0;
	int msg_length = 0;
	char msg[BUF_SIZE] = {0x00, };
	
	//클라이언트로부터 EOF를 받을 때까지
	while(read(clnt_sock, &msg_length, sizeof(msg_length)) != 0 ){
		msg_length = ntohl(msg_length);
		str_len = read_all(msg_length, clnt_sock, msg);
		if(msg_length != str_len || str_len == -1){//먼저 받은 데이터 크기와 실제 받은 데이터 크기가 같은지 비교
			printf("handle_clnt error, str_len = %d, msg_length = %d\n", str_len, msg_length);
			exit(EXIT_FAILURE);
		}
		pthread_mutex_lock(&mutx);
		hexdump("enc...", msg, str_len);
		pthread_mutex_unlock(&mutx);
		send_msg(clnt_sock, msg, str_len);
		memset(msg, 0, BUF_SIZE);
		msg_length = 0;
		str_len = 0;
	}
	//종료 신호를 보낸 해당 클라이언트 삭제
	pthread_mutex_lock(&mutx);
	for(int i=0;i<clnt_cnt;i++){
		if(clnt_sock == clnt_socks[i]){
			while(i<clnt_cnt-1){
				clnt_socks[i] = clnt_socks[i+1];
				i++;
			}
			break;
		}
	}
	--clnt_cnt;
	pthread_mutex_unlock(&mutx);
	
	close(clnt_sock);
	
	return NULL;
}

void send_msg(int clnt_sock, char *msg, int len){
	pthread_mutex_lock(&mutx);
	//메시지를 보낸 클라이언트 제외하고 모든 클라이언트에 메시지 전달
	int msg_length = 0;
	msg_length = htonl(len);
	for(int i=0;i<clnt_cnt;i++){
		if(clnt_socks[i] != clnt_sock){
			write(clnt_socks[i], &msg_length, sizeof(msg_length));//메세지를 보내기전, 크기부터보냄
			write(clnt_socks[i], msg, len);//크기룰 보낸 후 메시지를 보냄
		}
	}
	pthread_mutex_unlock(&mutx);
}

void error_handling(char* message){
	fputs(message, stderr);
	fputc('\n', stderr);
	exit(EXIT_FAILURE);
}













