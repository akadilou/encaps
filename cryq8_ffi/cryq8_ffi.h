#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void q8_free(uint8_t* p, size_t len);

int32_t q8_encpwd_json(const char* password,
                       const uint8_t* data, size_t data_len,
                       const char* mime,
                       const char* filename,
                       uint8_t** out_json, size_t* out_len);

int32_t q8_decpwd_json(const char* password,
                       const uint8_t* cap_json, size_t cap_len,
                       uint8_t** out_data, size_t* out_len);

int32_t q8_enckp_json(const char* sender_x25519_priv_b64,
                      const char* recipient_x25519_pub_b64,
                      const uint8_t* data, size_t data_len,
                      const char* mime,
                      const char* filename,
                      const char* sign_ed25519_priv_b64,
                      uint8_t** out_json, size_t* out_len);

int32_t q8_deckp_json(const char* recipient_x25519_priv_b64,
                      const uint8_t* cap_json, size_t cap_len,
                      const char* expect_sender_ed25519_pub_b64,
                      uint8_t** out_data, size_t* out_len);

int32_t q8_keygen_x_json(uint8_t** out_json, size_t* out_len);
int32_t q8_keygen_ed_json(uint8_t** out_json, size_t* out_len);

#ifdef __cplusplus
}
#endif
