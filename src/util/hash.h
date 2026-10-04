/* SPDX-License-Identifier: MIT */
#ifndef OMNI_HASH_H
#define OMNI_HASH_H

#include <stddef.h>
#include <stdint.h>

/* SipHash-2-4. Key is 16 bytes. */
uint64_t siphash24(const uint8_t key[16], const void *data, size_t len);

/*
 * Process-wide random key for hash tables (hash-flooding resistance).
 * Filled once by hash_init() from getrandom(); tests may call
 * hash_init_fixed() for determinism.
 */
extern uint8_t omni_hash_key[16];
void hash_init(void);
void hash_init_fixed(const uint8_t key[16]);

static inline uint64_t omni_hash(const void *data, size_t len)
{
	return siphash24(omni_hash_key, data, len);
}

/* Case-insensitive (ASCII) variant: hashes tolower() of every byte. */
uint64_t omni_hash_ci(const void *data, size_t len);

#endif
