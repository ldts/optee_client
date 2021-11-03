// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Foundries.io Ltd
 */

#ifndef BINARY_PREFIX
#define BINARY_PREFIX "seteec"
#endif

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <se.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <tee_client_api.h>
#include <teec_trace.h>

#include "scp03_ta.h"
#include "apdu_ta.h"

struct ta_context {
	TEEC_Context context;
	TEEC_Session session;
	pthread_mutex_t init_mutex;
	bool initiated;
};

static struct ta_context apdu_ta_ctx = {
	.init_mutex = PTHREAD_MUTEX_INITIALIZER,
};

static struct ta_context scp03_ta_ctx = {
	.init_mutex = PTHREAD_MUTEX_INITIALIZER,
};

static int se_init(TEEC_UUID *uuid, struct ta_context *ctx)
{
	uint32_t login_method = TEEC_LOGIN_PUBLIC;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	void *login_data = NULL;
	uint32_t origin = 0;
	int ret = 0;
	int e = 0;

	e = pthread_mutex_lock(&ctx->init_mutex);
	if (e) {
		EMSG("pthread_mutex_lock: %s", strerror(e));
		return e;
	}

	if (ctx->initiated)
		goto out;

	res = TEEC_InitializeContext(NULL, &ctx->context);
	if (res) {
		EMSG("TEEC init context failed, -ENODEV");
		ret = -ENODEV;
		goto out;
	}

	res = TEEC_OpenSession(&ctx->context, &ctx->session, uuid,
			       login_method, login_data, NULL, &origin);
	if (res) {
		EMSG("TEEC open session failed, -EPERM");
		ret = -EPERM;
		TEEC_FinalizeContext(&ctx->context);
		goto out;
	}

	ctx->initiated = true;
	return 0;

out:
	e = pthread_mutex_unlock(&apdu_ta_ctx.init_mutex);
	if (e)
		EMSG("pthread_mutex_unlock: %s", strerror(e));

	return ret;
}

int C_SE_apdu_request(enum se_apdu_type type,
		      unsigned char *hdr, size_t hdr_len,
		      unsigned char *src, size_t src_len,
		      unsigned char *dst, size_t *dst_len)
{
	TEEC_UUID uuid = TA_APDU_UUID;
	TEEC_Operation op = { 0 };
	uint32_t origin = 0;
	int ret = 0;

	ret = se_init(&uuid, &apdu_ta_ctx);
	if (ret)
		return ret;

	if (!src || !dst || (hdr && !hdr_len)) {
		EMSG("APDU invalid input parameters, -EINVAL");
		return -EINVAL;
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT);
	op.params[0].value.a = type;
	op.params[1].tmpref.buffer = hdr;
	op.params[1].tmpref.size = hdr_len;
	op.params[2].tmpref.buffer = src;
	op.params[2].tmpref.size = src_len;
	op.params[3].tmpref.buffer = dst;
	op.params[3].tmpref.size = *dst_len;

	if (TEEC_InvokeCommand(&apdu_ta_ctx.session,
			       TA_CMD_TXRX_APDU_RAW_FRAME, &op, &origin)) {
		EMSG("TEEC invoke command failed, -EINVAL");
		*dst_len = 0;
		return -EINVAL;
	}

	*dst_len = op.params[3].tmpref.size;
	if (*dst_len)
		return 0;

	EMSG("Processing in the Secure Element failed, -EIO");
	return -EACCES;
}

int C_SE_scp03_enable(void)
{
	TEEC_UUID uuid = TA_SCP03_UUID;
	TEEC_Operation op = { 0 };
	uint32_t origin = 0;
	int ret = 0;

	ret = se_init(&uuid, &scp03_ta_ctx);
	if (ret)
		return ret;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, 0, 0, 0);
	op.params[0].value.a = 0;

	if (TEEC_InvokeCommand(&scp03_ta_ctx.session,
			       TA_CMD_ENABLE_SCP03, &op, &origin)) {
		EMSG("TEEC invoke command failed, -EINVAL");
		return -EINVAL;
	}

	return 0;
}

int C_SE_scp03_rotate_keys(void)
{
	TEEC_UUID uuid = TA_SCP03_UUID;
	TEEC_Operation op = { 0 };
	uint32_t origin = 0;
	int ret = 0;

	ret = se_init(&uuid, &scp03_ta_ctx);
	if (ret)
		return ret;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, 0, 0, 0);
	op.params[0].value.a = 1;

	if (TEEC_InvokeCommand(&scp03_ta_ctx.session,
			       TA_CMD_ENABLE_SCP03, &op, &origin)) {
		EMSG("TEEC invoke command failed, -EINVAL");
		return -EINVAL;
	}

	return 0;
}
