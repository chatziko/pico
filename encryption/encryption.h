#ifndef _DECRYPT_H_
#define _DECRYPT_H_


// AES decryption
// Receives key/input as hex strings.
// Returns plaintext as binary string

char* decrypt(char* key, char* input);

// AES decryption
// Receives key as hex string, msg as binary string.
// Returns ciphertext as binary string
char* encrypt(char* key, char* msg);

#endif // _DECRYPT_H_