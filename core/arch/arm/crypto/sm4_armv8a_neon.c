// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2022. All rights reserved.
 *
 * - SM4 optimization for ARMv8 by NEON and AES HW instruction, 
 * - which is an optional Cryptographic Extension for ARMv8-A.
 */
#include <crypto/crypto_accel.h>
#include <kernel/thread.h>

void neon_sm4_setkey_enc(uint32_t sk[32], uint8_t const key[16]);
void neon_sm4_setkey_dec(uint32_t sk[32], uint8_t const key[16]);
void neon_sm4_ecb_encrypt(uint8_t out[], uint8_t const in[], uint8_t const rk[],
			  size_t len);
void neon_sm4_cbc_encrypt(uint8_t out[], uint8_t const in[], uint8_t const rk[],
			 size_t len, uint8_t iv[]);
void neon_sm4_cbc_decrypt(uint8_t out[], uint8_t const in[], uint8_t const rk[],
			  size_t len, uint8_t iv[]);
void neon_sm4_ctr_encrypt(uint8_t out[], uint8_t const in[], uint8_t const rk[],
			  size_t len, uint8_t iv[]);
void neon_sm4_xts_encrypt(uint8_t out[], uint8_t const in[],
			  uint8_t const rk1[], uint8_t const rk2[], size_t len,
			  uint8_t iv[]);
void neon_sm4_xts_decrypt(uint8_t out[], uint8_t const in[],
			  uint8_t const rk1[], uint8_t const rk2[], size_t len,
			  uint8_t iv[]);

void crypto_accel_sm4_setkey_enc(uint32_t sk[32], const uint8_t key[16])
{
	uint32_t vfp_state = 0;

	assert(sk && key);

	vfp_state = thread_kernel_enable_vfp();
	neon_sm4_setkey_enc(sk, key);
	thread_kernel_disable_vfp(vfp_state);
}

void crypto_accel_sm4_setkey_dec(uint32_t sk[32], const uint8_t key[16])
{
	uint32_t vfp_state = 0;

	assert(sk && key);

	vfp_state = thread_kernel_enable_vfp();
	neon_sm4_setkey_dec(sk, key);
	thread_kernel_disable_vfp(vfp_state);
}

void crypto_accel_sm4_ecb_enc(void *out, const void *in, const void *key,
			      unsigned int len)
{
	uint32_t vfp_state = 0;

	assert(out && in && key && !(len % 16));

	vfp_state = thread_kernel_enable_vfp();
	neon_sm4_ecb_encrypt(out, in, key, len);
	thread_kernel_disable_vfp(vfp_state);
}

void crypto_accel_sm4_cbc_enc(void *out, const void *in, const void *key,
			      unsigned int len, void *iv)
{
	uint32_t vfp_state = 0;

	assert(out && in && key && !(len % 16));

	vfp_state = thread_kernel_enable_vfp();
	neon_sm4_cbc_encrypt(out, in, key, len, iv);
	thread_kernel_disable_vfp(vfp_state);
}

void crypto_accel_sm4_cbc_dec(void *out, const void *in, const void *key,
			      unsigned int len, void *iv)
{
	uint32_t vfp_state = 0;

	assert(out && in && key && !(len % 16));

	vfp_state = thread_kernel_enable_vfp();
	neon_sm4_cbc_decrypt(out, in, key, len, iv);
	thread_kernel_disable_vfp(vfp_state);
}

void crypto_accel_sm4_ctr_enc(void *out, const void *in, const void *key,
			      unsigned int len, void *iv)
{
	uint32_t vfp_state = 0;

	assert(out && in && key && !(len % 16));

	vfp_state = thread_kernel_enable_vfp();
	neon_sm4_ctr_encrypt(out, in, key, len, iv);
	thread_kernel_disable_vfp(vfp_state);
}

void crypto_accel_sm4_xts_enc(void *out, const void *in, const void *key1,
			      const void *key2, unsigned int len, void *iv)
{
	uint32_t vfp_state = 0;

	assert(out && in && key1 && key2 && (len >= 16));

	vfp_state = thread_kernel_enable_vfp();
	neon_sm4_xts_encrypt(out, in, key1, key2, len, iv);
	thread_kernel_disable_vfp(vfp_state);
}

void crypto_accel_sm4_xts_dec(void *out, const void *in, const void *key1,
			      const void *key2, unsigned int len, void *iv)
{
	uint32_t vfp_state = 0;

	assert(out && in && key1 && key2 && (len >= 16));

	vfp_state = thread_kernel_enable_vfp();
	neon_sm4_xts_decrypt(out, in, key1, key2, len, iv);
	thread_kernel_disable_vfp(vfp_state);
}