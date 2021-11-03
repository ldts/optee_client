/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2020, Foundries Limited
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
 */

#ifndef APDU_PTA_H
#define APDU_PTA_H

#define PTA_APDU_UUID { 0x3f3eb880, 0x3639, 0x11ec, \
			{ 0x9b, 0x9d, 0x0f, 0x3f, 0xc9, 0x46, 0x8f, 0x50 } }
/*
 * ADPU based communication with a secure element
 *
 * Background Info: https://en.wikipedia.org/wiki/ISO/IEC_7816
 *
 * [in]  value[0].a           APDU request type.
 * [in]  memref[1].buffer     APDU header.
 * [in]  memref[1].size       APDU header len.
 * [in]  memref[2].buffer     source data (raw APDU request frame data).
 * [in]  memref[2].size       source len (raw APDU source frame length).
 * [out] memref[3].buffer     response data (raw APDU response frame data).
 * [out] memref[3].size       response len (raw APDU respose length).
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 * TEE_ERROR_NOT_IMPLEMENTED - Invoke command not implemented
 * TEE_ERROR_GENERIC - Invoke command failure
 */
#define PTA_CMD_TXRX_APDU_RAW_FRAME		0

#endif /* APDU_PTA_H */
