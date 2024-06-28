/** 
* This header file assumes that the definitions for 
* OQS_STATUS and OQS_SIG already exist elsewhere (Please refer to liboqs.), 
* and that the OQS_API macro has been defined to handle function export issues.	
**/

#ifndef OQS_CYPER_H
#define OQS_CYPER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// cla field
#define APDU_CLA_DEV_INIT 0x91
#define APDU_CLA_DEV_INIT_RSP 0x90
#define APDU_CLA_DEV_BUSY 0x7f
#define APDU_CLA_PARA_BAD 0x7e
#define APDU_CLA_ITRI 0x80
#define APDU_CLA_ITRI_RSP 0x81

// ins field
#define ALGO_KYBER_512 0xA1
#define ALGO_KYBER_768 0xA2
#define ALGO_KYBER_1024 0xA3
#define ALGO_DILITHIUM2 0xB1
#define ALGO_DILITHIUM3 0xB2
#define ALGO_DILITHIUM5 0xB3

// p1 field
#define CMD_KEM_KEYPAIR 0x01
#define CMD_KEM_ENCAP 0x02
#define CMD_KEM_DECAP 0x03
#define RSP_KEM_KEYPAIR 0x11
#define RSP_KEM_ENCAP 0x12
#define RSP_KEM_DECAP 0x13

#define CMD_DSA_KEYPAIR 0x21
#define CMD_DSA_SIGN1 0x22
#define CMD_DSA_VERIFY1 0x23
#define CMD_DSA_SIGN2 0x24
#define CMD_DSA_VERIFY2 0x25

#define RSP_DSA_KEYPAIR 0x31
#define RSP_DSA_SIGN 0x32
#define RSP_DSA_VERIFY 0x33

/** the length */
#define KYBER_512_PUBLICKEYBYTES 800
#define KYBER_512_SECRETKEYBYTES 1632
#define KYBER_512_CIPHERTEXTBYTES 768
#define KYBER_768_PUBLICKEYBYTES 1184
#define KYBER_768_SECRETKEYBYTES 2400
#define KYBER_768_CIPHERTEXTBYTES 1088
#define KYBER_1024_PUBLICKEYBYTES 1568
#define KYBER_1024_SECRETKEYBYTES 3168
#define KYBER_1024_CIPHERTEXTBYTES 1568
#define SSBYTES 32 


#define DILITHIUM2_PUBLICKEYBYTES 1312
#define DILITHIUM2_SECRETKEYBYTES 2528
#define DILITHIUM2_SIGNATUREBYTES 2420

#define DILITHIUM3_PUBLICKEYBYTES 1952
#define DILITHIUM3_SECRETKEYBYTES 4000
#define DILITHIUM3_SIGNATUREBYTES 3293

#define DILITHIUM5_PUBLICKEYBYTES 2592
#define DILITHIUM5_SECRETKEYBYTES 4864
#define DILITHIUM5_SIGNATUREBYTES 4595


/** Algorithm identifier for Kyber512 KEM. */
#define OQS_KEM_alg_kyber_512 "Kyber512"
/** Algorithm identifier for Kyber768 KEM. */
#define OQS_KEM_alg_kyber_768 "Kyber768"
/** Algorithm identifier for Kyber1024 KEM. */
#define OQS_KEM_alg_kyber_1024 "Kyber1024"

/** Number of algorithm identifiers above. */
#define OQS_KEM_algs_length 32


#if 0
/**
 * Key encapsulation mechanism object
 */
typedef struct OQS_KEM {

	/** Printable string representing the name of the key encapsulation mechanism. */
	const char *method_name;

	/**
	 * Printable string representing the version of the cryptographic algorithm.
	 *
	 * Implementations with the same method_name and same alg_version will be interoperable.
	 * See README.md for information about algorithm compatibility.
	 */
	const char *alg_version;

	/** The NIST security level (1, 2, 3, 4, 5) claimed in this algorithm's original NIST submission. */
	uint8_t claimed_nist_level;

	/** Whether the KEM offers IND-CCA security (TRUE) or IND-CPA security (FALSE). */
	bool ind_cca;

	/** The length, in bytes, of public keys for this KEM. */
	size_t length_public_key;
	/** The length, in bytes, of secret keys for this KEM. */
	size_t length_secret_key;
	/** The length, in bytes, of ciphertexts for this KEM. */
	size_t length_ciphertext;
	/** The length, in bytes, of shared secrets for this KEM. */
	size_t length_shared_secret;

	/**
	 * Keypair generation algorithm.
	 *
	 * Caller is responsible for allocating sufficient memory for `public_key` and
	 * `secret_key`, based on the `length_*` members in this object or the per-scheme
	 * compile-time macros `OQS_KEM_*_length_*`.
	 *
	 * @param[out] public_key The public key represented as a byte string.
	 * @param[out] secret_key The secret key represented as a byte string.
	 * @return OQS_SUCCESS or OQS_ERROR
	 */
	OQS_STATUS (*keypair)(uint8_t *public_key, uint8_t *secret_key);

	/**
	 * Encapsulation algorithm.
	 *
	 * Caller is responsible for allocating sufficient memory for `ciphertext` and
	 * `shared_secret`, based on the `length_*` members in this object or the per-scheme
	 * compile-time macros `OQS_KEM_*_length_*`.
	 *
	 * @param[out] ciphertext The ciphertext (encapsulation) represented as a byte string.
	 * @param[out] shared_secret The shared secret represented as a byte string.
	 * @param[in] public_key The public key represented as a byte string.
	 * @return OQS_SUCCESS or OQS_ERROR
	 */
	OQS_STATUS (*encaps)(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);

	/**
	 * Decapsulation algorithm.
	 *
	 * Caller is responsible for allocating sufficient memory for `shared_secret`, based
	 * on the `length_*` members in this object or the per-scheme compile-time macros
	 * `OQS_KEM_*_length_*`.
	 *
	 * @param[out] shared_secret The shared secret represented as a byte string.
	 * @param[in] ciphertext The ciphertext (encapsulation) represented as a byte string.
	 * @param[in] secret_key The secret key represented as a byte string.
	 * @return OQS_SUCCESS or OQS_ERROR
	 */
	OQS_STATUS (*decaps)(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);

} OQS_KEM;

#define OQS_ENABLE_SIG_dilithium_2      1

#if defined(OQS_ENABLE_SIG_dilithium_2)
#define OQS_SIG_dilithium_2_length_public_key 1312
#define OQS_SIG_dilithium_2_length_secret_key 2528
#define OQS_SIG_dilithium_2_length_signature 2420

OQS_SIG *OQS_SIG_dilithium_2_new(void);
OQS_API OQS_STATUS OQS_SIG_dilithium_2_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_dilithium_2_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_dilithium_2_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_dilithium_3)
#define OQS_SIG_dilithium_3_length_public_key 1952
#define OQS_SIG_dilithium_3_length_secret_key 4000
#define OQS_SIG_dilithium_3_length_signature 3293

OQS_SIG *OQS_SIG_dilithium_3_new(void);
OQS_API OQS_STATUS OQS_SIG_dilithium_3_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_dilithium_3_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_dilithium_3_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_dilithium_5)
#define OQS_SIG_dilithium_5_length_public_key 2592
#define OQS_SIG_dilithium_5_length_secret_key 4864
#define OQS_SIG_dilithium_5_length_signature 4595

OQS_SIG *OQS_SIG_dilithium_5_new(void);
OQS_API OQS_STATUS OQS_SIG_dilithium_5_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_dilithium_5_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_dilithium_5_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#endif

#endif // OQS_CYPER_H

