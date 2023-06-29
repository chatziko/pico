#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>

#include "aes.h"
#include "encryption.h"

// AES ciphertext needs to be in blocks of 16 bytes. To allow arbitrary sizes, we use PKCS-7 padding.
static int check_pkcs7_padding(uint8_t* msg, int size) {
	// The last byte determines how many padding bytes we have
	uint8_t padding_size = msg[size-1];

	if(padding_size > size || padding_size < 1 || padding_size > 16)
		return -1;

	// All padding bytes are identical (contain the number of padding bytes)
	for(int i = 0; i < padding_size; i++)
		if(msg[size-1-i] != padding_size)
			return -1;
	
	return padding_size;
}

static uint8_t* hex_to_bin(char* hex) {
	int size = strlen(hex);
	uint8_t* res = malloc(size/2);
	for(int i = 0; i < size/2; i++) {
		unsigned int byte;
		sscanf(&hex[2*i], "%2x", &byte);
		res[i] = byte;
	}

	return res;
}

char* decrypt(char* key, char* msg) {
	int msg_size = strlen(msg)/2;
	if(msg_size % AES_BLOCKLEN != 0 || strlen(key)/2 != AES_KEYLEN)
		return NULL;

	uint8_t* msg_bin = hex_to_bin(msg);
	uint8_t* key_bin = hex_to_bin(key);

	// Decrypt
	uint8_t* iv = &msg_bin[0];						// First block is the Initialization Vector
	uint8_t* ciphertext = &msg_bin[AES_BLOCKLEN];	// Ciphertext: all other blocks
	int ciphertext_size = msg_size - AES_BLOCKLEN;

	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key_bin, iv);
	AES_CBC_decrypt_buffer(&ctx, ciphertext, ciphertext_size);	// in-place decrypt, ciphertext now contains the plaintext

	free(key_bin);

	// Remove PKCS-7 padding
	int padding_size = check_pkcs7_padding(ciphertext, ciphertext_size);
	if(padding_size < 0) {
		free(msg_bin);
		return NULL;
	}

	int plaintext_size = ciphertext_size - padding_size;
	char* result = malloc(plaintext_size + 1);
	strncpy(result, ciphertext, plaintext_size);
	result[plaintext_size] = '\0';

	free(msg_bin);

	return result;
}

char* encrypt(char* key, char* msg) {
	srand(time(NULL));

	if(strlen(key)/2 != AES_KEYLEN)
		return NULL;

	uint8_t* key_bin = hex_to_bin(key);

	int msg_size = strlen(msg);
	msg_size += AES_BLOCKLEN;	// 1 block for the IV
	int padding_size = AES_BLOCKLEN - msg_size % AES_BLOCKLEN;
	msg_size += padding_size;

	uint8_t* res_bin = malloc(msg_size);

	// first the IV
	for(int i = 0; i < AES_BLOCKLEN; i++)
		res_bin[i] = rand() % 256;

	// then the message
	strcpy(&res_bin[AES_BLOCKLEN], msg);
	
	// then the padding
	for(int i = 0; i < padding_size; i++)
		res_bin[msg_size - 1 - i] = padding_size;

	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key_bin, res_bin);	// First block is the Initialization Vector

	AES_CBC_encrypt_buffer(&ctx, &res_bin[AES_BLOCKLEN], msg_size);

	// to hex
	char* res = malloc(msg_size * 2 + 1);
	res[msg_size*2] = '\0';
	for(int i = 0; i < msg_size; i++)
		sprintf(&res[2*i], "%02x", res_bin[i]);

	return res;
}
