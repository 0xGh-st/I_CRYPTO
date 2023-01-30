#define _CRT_SECURE_NO_WARNINGS
#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "edge_crypto.h"
#include "i_crypto.h"
#include "org_example_JNI_I_SYM.h"
#ifdef _WIN32
#include <windows.h>
#else
#include <stdarg.h>
#endif
#include <time.h>

//hexdump
JNIEXPORT void JNICALL Java_org_example_JNI_1I_1SYM_hexdump
(JNIEnv* env, jobject obj, jstring title, jbyteArray mem, jint len) {
	const char* cString = (*env)->GetStringUTFChars(env, title, NULL);
	jbyteArray input = (*env)->GetByteArrayElements(env, mem, NULL);
	hexdump(cString, input, (int)len);
	(*env)->ReleaseStringUTFChars(env, title, cString);
}

// crypto init, final
JNIEXPORT jint JNICALL Java_org_example_JNI_1I_1SYM_edge_1crypto_1init
(JNIEnv* env, jobject obj) {
	int ret = 0;
	ret = edge_crypto_init(NULL);
	return (jint)ret;
}

JNIEXPORT jint JNICALL Java_org_example_JNI_1I_1SYM_edge_1crypto_1final
(JNIEnv* env, jobject obj) {
	edge_crypto_final();
}

//new Func. getCipehrID, init EDGE_CIPHER_PARAMETERS, init_key 
JNIEXPORT jint JNICALL Java_org_example_JNI_1I_1SYM_getCipherID
(JNIEnv* env, jobject obj) {
	return (jint)EDGE_CIPHER_ID_ARIA128;
}

JNIEXPORT jlong JNICALL Java_org_example_JNI_1I_1SYM_init_1EDGE_1CIPHER_1PARAMETERS
(JNIEnv* env, jobject obj) {
	EDGE_CIPHER_PARAMETERS* param = (EDGE_CIPHER_PARAMETERS*)malloc(sizeof(EDGE_CIPHER_PARAMETERS));
	if (param == NULL) return -1;
	uint8_t iv[16] = { 0x00, };
	uint32_t ivlength = 16;
	memset(param, 0, sizeof(EDGE_CIPHER_PARAMETERS));
	param->m_mode = EDGE_CIPHER_MODE_CBC;
	param->m_padding = EDGE_CIPHER_PADDING_PKCS5;
	param->m_modeparam.m_modesize = 16;
	memcpy(param->m_modeparam.m_iv, iv, ivlength);
	param->m_modeparam.m_ivlength = ivlength;

	return (jlong)param;
}

JNIEXPORT void JNICALL Java_org_example_JNI_1I_1SYM_init_1key
(JNIEnv* env, jobject obj, jbyteArray p_key) {
	uint8_t key[16] = { 0x00, };
	uint32_t keylength = 16;
	edge_random_byte(key, keylength);

	(*env)->SetByteArrayRegion(env, p_key, 0, keylength, (jbyte*)key);
}

JNIEXPORT jint JNICALL Java_org_example_JNI_1I_1SYM_i_1enc
(JNIEnv* env, jobject obj, jint p_cipher_id, jbyteArray p_key, jint p_keylength, jlong p_param, jbyteArray p_input, jint p_inputlength, jbyteArray p_output, jintArray p_outputlength) {
	int ret = 0;
	//for using data in C from java
	int cipher_id = (int)p_cipher_id;
	jbyteArray key = (*env)->GetByteArrayElements(env, p_key, NULL);
	uint32_t keylength = (uint32_t)p_keylength;
	EDGE_CIPHER_PARAMETERS* param = (EDGE_CIPHER_PARAMETERS*)p_param;
	jbyteArray input = (*env)->GetByteArrayElements(env, p_input, NULL);
	
	uint32_t inputlength = (uint32_t)p_inputlength;
	uint8_t output[1024];
	uint32_t outputlength = 0;

	ret = i_enc(cipher_id, (uint8_t*)key, keylength, param, (uint8_t*)input, inputlength, output, &outputlength);
	if (ret != 0) return (jint)ret;

	(*env)->SetByteArrayRegion(env, p_output, 0, (jint)outputlength, (jbyte*)output);
	(*env)->SetIntArrayRegion(env, p_outputlength, 0, (jint)1, (jint*)&outputlength);
	return (jlong)ret;
}

JNIEXPORT jint JNICALL Java_org_example_JNI_1I_1SYM_i_1dec
(JNIEnv* env, jobject obj, jint p_cipher_id, jbyteArray p_key, jint p_keylength, jlong p_param, jbyteArray p_input, jint p_inputlength, jbyteArray p_output, jintArray p_outputlength) {
	int ret = 0;
	//for using data in C from java
	int cipher_id = (int)p_cipher_id;
	jbyteArray key = (*env)->GetByteArrayElements(env, p_key, NULL);
	uint32_t keylength = (uint32_t)p_keylength;
	EDGE_CIPHER_PARAMETERS* param = (EDGE_CIPHER_PARAMETERS*)p_param;
	jbyteArray input = (*env)->GetByteArrayElements(env, p_input, NULL);
	uint32_t inputlength = (uint32_t)p_inputlength;
	uint8_t output[1024];
	uint32_t outputlength = 0;

	ret = i_dec(cipher_id, (uint8_t*)key, keylength, param, (uint8_t*)input, inputlength, output, &outputlength);
	if (ret != 0) return (jint)ret;

	(*env)->SetByteArrayRegion(env, p_output, 0, (jint)outputlength, (jbyte*)output);
	(*env)->SetIntArrayRegion(env, p_outputlength, 0, (jint)1, (jint*)&outputlength);

	return (jlong)ret;
}

JNIEXPORT jlong JNICALL Java_org_example_JNI_1I_1SYM_i_1ctx_1new
(JNIEnv* env, jobject obj) {
	I_CIPHER_CTX* ctx;
	ctx = i_ctx_new();
	return (jlong)ctx;
}

JNIEXPORT void JNICALL Java_org_example_JNI_1I_1SYM_i_1ctx_1reset
(JNIEnv* env, jobject obj, jlong p_context) {
	i_ctx_reset((I_CIPHER_CTX*)p_context);
	return;
}

JNIEXPORT void JNICALL Java_org_example_JNI_1I_1SYM_i_1ctx_1free
(JNIEnv* env, jobject obj, jlong p_context) {
	i_ctx_free((I_CIPHER_CTX*)p_context);
	return;
}

JNIEXPORT jint JNICALL Java_org_example_JNI_1I_1SYM_i_1enc_1init
(JNIEnv* env, jobject obj, jlong p_context, jint p_cipher_id, jbyteArray p_key, jint p_keylength, jlong p_param) {
	int ret = 0;
	jbyteArray key = (*env)->GetByteArrayElements(env, p_key, NULL);
	ret = i_enc_init((I_CIPHER_CTX*)p_context, (int)p_cipher_id, (uint8_t*)key, (uint32_t)p_keylength, (EDGE_CIPHER_PARAMETERS*)p_param);
	return (jint)ret;
}

JNIEXPORT jint JNICALL Java_org_example_JNI_1I_1SYM_i_1enc_1update
(JNIEnv* env, jobject obj, jlong p_context, jbyteArray p_input, jint p_inputlength, jbyteArray p_output, jintArray p_outputlength) {
	int ret = 0;
	//for using data in C from java
	I_CIPHER_CTX* ctx = (I_CIPHER_CTX*)p_context;
	jbyteArray input = (*env)->GetByteArrayElements(env, p_input, NULL);
	uint32_t inputlength = (uint32_t)p_inputlength;
	uint8_t output[1024];
	uint32_t outputlength = 0;
	
	ret = i_enc_update(ctx, (uint8_t*)input, inputlength, output, &outputlength);
	if (ret != 0) return ret;

	(*env)->SetByteArrayRegion(env, p_output, 0, (jint)outputlength, (jbyte*)output);
	(*env)->SetIntArrayRegion(env, p_outputlength, 0, (jint)1, (jint*)&outputlength);

	return ret;
}

JNIEXPORT jint JNICALL Java_org_example_JNI_1I_1SYM_i_1enc_1final
(JNIEnv* env, jobject obj, jlong p_context, jbyteArray p_output, jintArray p_outputlength) {
	int ret = 0;
	//for using data in C from java
	I_CIPHER_CTX* ctx = (I_CIPHER_CTX*)p_context;
	uint8_t output[1024];
	uint32_t outputlength = 0;

	ret = i_enc_final(ctx, output, &outputlength);
	if (ret != 0) return ret;

	(*env)->SetByteArrayRegion(env, p_output, 0, (jint)outputlength, (jbyte*)output);
	(*env)->SetIntArrayRegion(env, p_outputlength, 0, (jint)1, (jint*)&outputlength);

	return ret;
}

JNIEXPORT jint JNICALL Java_org_example_JNI_1I_1SYM_i_1dec_1init
(JNIEnv* env, jobject obj, jlong p_context, jint p_cipher_id, jbyteArray p_key, jint p_keylength, jlong p_param) {
	int ret = 0;
	jbyteArray key = (*env)->GetByteArrayElements(env, p_key, NULL);
	ret = i_dec_init((I_CIPHER_CTX*)p_context, (int)p_cipher_id, (uint8_t*)key, (uint32_t)p_keylength, (EDGE_CIPHER_PARAMETERS*)p_param);
	return (jint)ret;
}

JNIEXPORT jint JNICALL Java_org_example_JNI_1I_1SYM_i_1dec_1update
(JNIEnv* env, jobject obj, jlong p_context, jbyteArray p_input, jint p_inputlength, jbyteArray p_output, jintArray p_outputlength) {
	int ret = 0;
	//for using data in C from java
	I_CIPHER_CTX* ctx = (I_CIPHER_CTX*)p_context;
	jbyteArray input = (*env)->GetByteArrayElements(env, p_input, NULL);
	uint32_t inputlength = (uint32_t)p_inputlength;
	uint8_t output[1024];
	uint32_t outputlength = 0;

	ret = i_dec_update(ctx, (uint8_t*)input, inputlength, output, &outputlength);
	if (ret != 0) return ret;

	(*env)->SetByteArrayRegion(env, p_output, 0, (jint)outputlength, (jbyte*)output);
	(*env)->SetIntArrayRegion(env, p_outputlength, 0, (jint)1, (jint*)&outputlength);

	return ret;
}

JNIEXPORT jint JNICALL Java_org_example_JNI_1I_1SYM_i_1dec_1final
(JNIEnv* env, jobject obj, jlong p_context, jbyteArray p_output, jintArray p_outputlength, jintArray p_paddinglength) {
	int ret = 0;
	uint32_t paddinglength = 0;
	//for using data in C from java
	I_CIPHER_CTX* ctx = (I_CIPHER_CTX*)p_context;
	//jbyteArray output = (*env)->GetByteArrayElements(env, p_output, NULL);
	//jintArray outputlength = (*env)->GetIntArrayElements(env, p_output, NULL);
	//printf("%s\n", (uint8_t*)output);
	ret = i_dec_final(ctx, NULL, NULL, (uint32_t*)&paddinglength);
	//ret = i_dec_final(ctx, (uint8_t*)output, (uint32_t*)outputlength, (uint32_t*)&paddinglength);
	if (ret != 0) return ret;

	(*env)->SetIntArrayRegion(env, p_paddinglength, 0, (jint)1, (jint*)&paddinglength);

	return ret;
}


