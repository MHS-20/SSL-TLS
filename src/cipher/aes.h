#ifndef AES_H
#define AES_H

#define AES_BLOCK_SIZE 16

void aes_128_encrypt( const unsigned char *plaintext, const int plaintext_len,
                      unsigned char ciphertext[], void *iv,
                      const unsigned char *key );
void aes_128_decrypt( const unsigned char *ciphertext, const int ciphertext_len,
                      unsigned char plaintext[], void *iv,
                      const unsigned char *key );
void aes_256_encrypt( const unsigned char *plaintext, const int plaintext_len,
                      unsigned char ciphertext[], void *iv,
                      const unsigned char *key );
void aes_256_decrypt( const unsigned char *ciphertext, const int ciphertext_len,
                      unsigned char plaintext[], void *iv,
                      const unsigned char *key );

#define MAC_LENGTH 8

void aes_ctr_encrypt( const unsigned char *input, int input_len,
                      unsigned char *output, void *iv,
                      const unsigned char *key );
void aes_cbc_mac( const unsigned char *key, int key_length,
                  const unsigned char *text, int text_length,
                  unsigned char *mac );
int aes_ccm_encrypt( const unsigned char *input, const int input_len,
                     const unsigned char *addldata, const int addldata_len,
                     unsigned char output[], void *iv,
                     const unsigned char *key );
int aes_ccm_decrypt( const unsigned char *input, const int input_len,
                     const unsigned char *addldata, const int addldata_len,
                     unsigned char output[], void *iv,
                     const unsigned char *key );
int aes_gcm_encrypt( const unsigned char *input, const int input_len,
                     const unsigned char *addldata, const int addldata_len,
                     unsigned char output[], void *iv,
                     const unsigned char *key );
int aes_gcm_decrypt( const unsigned char *input, const int input_len,
                     const unsigned char *addldata, const int addldata_len,
                     unsigned char output[], void *iv,
                     const unsigned char *key );

#endif
