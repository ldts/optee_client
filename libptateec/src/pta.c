// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, Foundries.io Ltd
 */

#ifndef BINARY_PREFIX
#define BINARY_PREFIX "ptateec"
#endif

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <pta_tee.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <tee_client_api.h>
#include <teec_trace.h>

/* Supported PTAs */
#include "pta_imx_manufacturing_protection.h"

struct ta_context {
	pthread_mutex_t lock;
	TEEC_Context context;
	TEEC_Session session;
	TEEC_UUID uuid;
	bool open;
};

static struct ta_context manufacturing_protection_ta_ctx = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.uuid = PTA_MANUFACT_PROTEC_UUID,
};

static bool open_session(struct ta_context *ctx)
{
	TEEC_Result res = TEEC_SUCCESS;

	if (pthread_mutex_lock(&ctx->lock))
		return false;

	if (!ctx->open) {
		res = TEEC_InitializeContext(NULL, &ctx->context);
		if (!res) {
			res = TEEC_OpenSession(&ctx->context, &ctx->session,
					       &ctx->uuid, TEEC_LOGIN_PUBLIC,
					       NULL, NULL, NULL);
			if (!res)
				ctx->open = true;
		}
	}

	return !pthread_mutex_unlock(&ctx->lock) && !res;
}

PTA_RV pta_imx_mprotect_get_key(char *key, size_t *len)
{
	TEEC_Operation op = { 0 };
	char buffer[256] = { };

	if (!key || !len || !*len)
		return PTAR_ERROR_GENERIC;

	if (!open_session(&manufacturing_protection_ta_ctx))
		return PTAR_CANT_OPEN_SESSION;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = buffer;
	op.params[0].tmpref.size = sizeof(buffer);

	if (TEEC_InvokeCommand(&manufacturing_protection_ta_ctx.session,
			       PTA_IMX_MP_CMD_GET_PUBLIC_KEY, &op, NULL))
		return PTAR_ERROR_GENERIC;

	if (op.params[0].tmpref.size > *len)
		return PTAR_SMALL_BUFFER;

	*len = op.params[0].tmpref.size;
	memcpy(key, buffer, *len);

	return PTAR_OK;
}

PTA_RV pta_imx_mprotect_sign(char *msg, size_t msg_len,
                             char *sig, size_t *sig_len,
                             char *mpmr, size_t *mpmr_len)
{
	TEEC_Operation op = { 0 };

	if (!msg || !sig || !sig_len || !mpmr || !mpmr_len)
		return PTAR_ERROR_GENERIC;

	if (!msg_len || !*sig_len || !*mpmr_len)
		return PTAR_ERROR_GENERIC;

	if (!open_session(&manufacturing_protection_ta_ctx))
		return PTAR_CANT_OPEN_SESSION;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

	op.params[0].tmpref.buffer = msg;
	op.params[0].tmpref.size = msg_len;
	op.params[1].tmpref.buffer = sig;
	op.params[1].tmpref.size = *sig_len;
	op.params[2].tmpref.buffer = mpmr;
	op.params[2].tmpref.size =  *mpmr_len;

	if (TEEC_InvokeCommand(&manufacturing_protection_ta_ctx.session,
			       PTA_IMX_MP_CMD_SIGNATURE_MPMR, &op, NULL))
		return PTAR_ERROR_GENERIC;

	*sig_len = op.params[1].tmpref.size;
	*mpmr_len = op.params[2].tmpref.size;

	return PTAR_OK;
}
