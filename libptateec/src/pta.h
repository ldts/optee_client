/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023, Foundries.io Ltd
 */
#ifndef PTA_H
#define PTA_H

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <pta_tee.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <tee_client_api.h>
#include <teec_trace.h>

struct ta_context {
	pthread_mutex_t lock;
	TEEC_Context context;
	TEEC_Session session;
	TEEC_UUID uuid;
	bool open;
	atomic_int count;
};

TEEC_Result pta_open_session(struct ta_context *ctx);
TEEC_Result pta_invoke_cmd(struct ta_context *ctx, uint32_t cmd_id,
			   TEEC_Operation *operation, uint32_t *error_origin);
TEEC_Result pta_final(struct ta_context *ctx);

#endif
