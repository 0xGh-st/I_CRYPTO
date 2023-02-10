/**
* @section Encoding
* UTF-8
* @author ybkim
* @copyright secucen
*/

#include <stdio.h>
#include <stdlib.h>

#define MIN_DIGIT 6
#define MAX_DIGIT 16
#define MIN_KEY_LENGTH 32
#define MAX_KEY_LENGTH 64
#define STATIC_MODE 1
#define DYNAMIC_MODE 2
#define MIN_LIFE_TIME 30
#define MAX_LIFE_TIME 120

/**
* @brief edge crypto에서 제공하는 edge_crypto_init() 래핑 함수
*/
int otp_init();

/**
* @brief edge crypto에서 제공하는 edge_crypto_final() 래핑 함수
*/
void otp_final();

/**
* @brief otp 정보에 관한 값들에 대한 유효성 검증 함수
* @return int 성공시 0, 실패시 -1
*/
int otp_option_validator	(const unsigned int serialNumDigit, const unsigned int keyLength,
							const unsigned int otpDigit, const unsigned int lifeTime,
							const unsigned int mode, const unsigned int EXTRACT_START_INDEX,
							const unsigned int EXTRACT_SIZE);

/**
* @brief OTP 기기 생성을 위해 필요한 시리얼 번호 생성 함수
* @return void
*/
void set_serial_number      (char* serialNum, unsigned int serialNumDigit);

/**
* @brief OTP 기기 생성을 위해 필요한 키 생성 함수
* @return void
*/
void set_key                (char* key, unsigned int keyLength);

/**
* @brief otp기기의 시리얼 번호를 카드에 write
* @param FILE* fp 시리얼 번호 카드
* @return int 성공시 0, 실패시 그 외 
*/
int write_serial_number     (FILE* const fp,
                            const char* const serialNum,
                            const unsigned int serialNumDigit);

/**
* @brief otp기기 하드디스크에 필요한 정보 저장
* @param FILE* fp otp 하드디스크
* @return int 성공시 0, 실패시 -1
*/
int write_otpHD				(FILE* const fp,
							const char* const key, const unsigned int keyLength, 
							const unsigned int otpDigit, const unsigned int lifeTime,
							const unsigned int mode, const unsigned int EXTRACT_START_INDEX,
							const unsigned int EXTRACT_SIZE);
/**
* @brief 서버 DB에 시리얼넘버와 그 번호에 해당하는 기계의 정보를 저장
* @param FILE* fp Server DB
* @return int 성공시 0, 실패시 그 외
*/
int write_serverDB          (FILE* const fp,
                            const char* const serialNum, const unsigned int serialNumDigit,
                            const char* const key, const unsigned int keyLength,
                            const unsigned int otpDigit, const unsigned int lifetime,
                            const unsigned int mode, const unsigned int EXTRACT_START_INDEX,
                            const unsigned int EXTRACT_SIZE);

/**
* @brief Settings에서 otp 기기 생성시 필요한 정보를 가져온다.  
* @param FILE* fp Settings
* @return int 성공시 0, 실패시 그 외 
*/
int read_settings			(FILE* const fp, 
							unsigned int* serialNumDigit, unsigned int* keyLength, 
							unsigned int* otpDigit, unsigned int* lifeTime, 
							unsigned int* mode, unsigned int* EXTRACT_START_INDEX, 
							unsigned int* EXTRACT_SIZE);

/**
* @brief 서버 DB에서 시리얼 넘버와 매칭시켜 otp 정보를 가져온다.
* @param FILE* fp Server DB
* @return int 성공시 0, 실패시 그 외
*/
int read_OTP_info           (FILE* const fp,
                            char *serialNum, unsigned int serialNumDigit,
                            char *key, unsigned int *keyLength,
                            unsigned int *otpDigit, unsigned int *lifeTime,
                            unsigned int *mode, unsigned int *EXTRACT_START_INDEX,
                            unsigned int *EXTRACT_SIZE, unsigned int *offset);

/**
* @brief otp번호 생성기
* @return unsigned int 성공시 otp번호, 실패시 0 
*/
unsigned int generateOTP    (time_t currentTime,
                            char *key, unsigned int keyLength,
                            unsigned int otpDigit, unsigned int lifeTime,
                            unsigned int mode, unsigned int EXTRACT_START_INDEX,
                            unsigned int EXTRACT_SIZE);

/**
* @brief otp 검증
* @param unsigned int input 사용자에게 입력받은 otp번호
* return int 성공시 0, 실패시 그 외
*/
int verifyOTP               (unsigned int input, unsigned int validTime,
                            char *key, unsigned int keyLength,
                            unsigned int otpDigit, unsigned int lifeTime,
                            unsigned int mode, unsigned int EXTRACT_START_INDEX,
                            unsigned int EXTRACT_SIZE, unsigned int offset);
