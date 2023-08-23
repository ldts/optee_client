/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023, Foundries.io
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
 */

#ifndef PTA_TEE_H
#define PTA_TEE_H

#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned long PTA_ULONG;
typedef PTA_ULONG PTA_RV;

/* Values for type PTA_RV */
#define PTAR_OK					0x0000
#define PTAR_CANT_OPEN_SESSION			0x0001
#define PTAR_ERROR_GENERIC			0x0002
#define PTAR_SMALL_BUFFER			0x0003

/**
 * pta_imx_mprotect_get_key() - Retrieves the iMX CAAM Manufacturing Protection
 * EC public key. The components x,y are retrieved in RAW format and should
 * be converted to DER or PEM as required.
 *
 * For the 256 bit curve, this will generate two 32byte components therefore
 * requiring at least a 64 byte buffer.
 *
 * @return PTAR_CANT_OPEN_SESSION	Error opening the TEE session.
 * @return PTAR_ERROR_GENERIC		Error unspecified.
 * @return PTAR_SMALL_BUFFER		Error small buffer provided
 * @return PTAR_OK			On success.
 *
 */
PTA_RV pta_imx_mprotect_get_key(char *key, size_t *len);

/**
 * pta_imx_mprotect_sign() - Signs a message buffer using the Manufacturing
 * Protection EC private key present in the iMX CAAM.
 *
 * @return PTAR_CANT_OPEN_SESSION	Error opening the TEE session.
 * @return PTAR_ERROR_GENERIC		Error unspecified.
 * @return PTAR_SMALL_BUFFER		Error small buffer provided
 * @return PTAR_OK			On success.
 *
 */
PTA_RV pta_imx_mprotect_sign(char *message, size_t mlen,
                             char *signature, size_t *slen,
                             char *mpmr, size_t *len);

#ifdef __cplusplus
}
#endif

#endif /*PTA_TEE_H*/
