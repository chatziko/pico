#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "aes.h"

// AES ciphertext needs to be in blocks of 16 bytes. To allow arbitrary sizes, we use PKCS-7 padding.
int check_pkcs7_padding(uint8_t* msg, int size) {
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

int main(int argc, char* argv[]) {
	// read the key
	FILE *key_file = fopen("key", "r");
	if(!key_file) {
		printf("cannot read key\n");
		return 1;
	}
	uint8_t key[AES_BLOCKLEN];
	fread(key, 1, AES_BLOCKLEN, key_file);
	fclose(key_file);

	// read message from stdin
	uint8_t message[200];
	int size = fread(message, 1, sizeof(message), stdin);
	if(size % AES_BLOCKLEN != 0) {
		printf("invalid size\n");
		return 1;
	}

	// Decrypt
	uint8_t* iv = &message[0];						// First block is the Initialization Vector
	uint8_t* ciphertext = &message[AES_BLOCKLEN];	// Ciphertext: all other blocks
	int ciphertext_size = size - AES_BLOCKLEN;

	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key, iv);
	AES_CBC_decrypt_buffer(&ctx, ciphertext, ciphertext_size);	// in-place decrypt, ciphertext now contains the plaintext

	// Remove PKCS-7 padding
	int padding_size = check_pkcs7_padding(ciphertext, ciphertext_size);
	if(padding_size < 0) {
		printf("invalid padding\n");
		return 1;
	}

	ciphertext_size -= padding_size;
	ciphertext[ciphertext_size] = 0;

	// Check that the plaintext secret is correct
	FILE *secret_file = fopen("secret", "r");
	if(!secret_file) {
		printf("cannot open secret\n");
		return 1;
	}
	int ok = 1;
	for(int i = 0; i < ciphertext_size; i++) {
		if(fgetc(secret_file) != ciphertext[i])
			ok = 0;
	}
	if(fgetc(secret_file) != '\n')
		ok = 0;

	// Secret is correct
	printf(ok ? "secret ok\n" : "wrong secret\n");
}


