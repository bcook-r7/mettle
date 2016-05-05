/**
 * Copyright 2015 Rapid7
 * @brief Meterpreter-style Type/length/value packet handler
 * @file tlv.h
 */

#ifndef _TLV_H_
#define _TLV_H_

#include <stdbool.h>
#include <stdint.h>

#include <dnet.h>

#include "buffer_queue.h"
#include "tlv_types.h"

/*
 * TLV Packets
 */
struct tlv_packet;

struct tlv_packet *tlv_packet_new(uint32_t type, int initial_len);

struct tlv_packet * tlv_packet_read_buffer_queue(struct buffer_queue *q);

void *tlv_packet_data(struct tlv_packet *p);

int tlv_packet_len(struct tlv_packet *p);

char *tlv_packet_get_buf_str(void * buf, size_t len);

void *tlv_packet_get_raw(struct tlv_packet *p, uint32_t raw_type, size_t *len);

char *tlv_packet_get_str(struct tlv_packet *p, uint32_t value_type);

int tlv_packet_get_u16(struct tlv_packet *p, uint32_t value_type, uint16_t *value);

int tlv_packet_get_u32(struct tlv_packet *p, uint32_t value_type, uint32_t *value);

int tlv_packet_get_u64(struct tlv_packet *p, uint32_t value_type, uint64_t *value);

struct tlv_iterator {
	struct tlv_packet *packet;
	size_t offset;
	uint32_t value_type;
};

void *tlv_packet_iterate(struct tlv_iterator *i, size_t *len);

char *tlv_packet_iterate_str(struct tlv_iterator *i);

struct tlv_packet * tlv_packet_add_child_raw(struct tlv_packet *p,
		const void *val, size_t len);

struct tlv_packet * tlv_packet_add_child(struct tlv_packet *p,
		struct tlv_packet *child);

struct tlv_packet * tlv_packet_add_raw(struct tlv_packet *p,
		uint32_t type, const void *val, size_t len);

struct tlv_packet * tlv_packet_add_str(struct tlv_packet *p,
		uint32_t type, const char *str);

struct tlv_packet * tlv_packet_add_fmt(struct tlv_packet *p,
		uint32_t type, char const *fmt, ...)
		__attribute__ ((format(printf, 3, 4)));

struct tlv_packet * tlv_packet_add_u32(struct tlv_packet *p,
		uint32_t type, uint32_t val);

struct tlv_packet * tlv_packet_add_u64(struct tlv_packet *p,
		uint32_t type, uint64_t val);

struct tlv_packet * tlv_packet_add_bool(struct tlv_packet *p,
		uint32_t type, bool val);

struct tlv_packet * tlv_packet_add_addr(struct tlv_packet *p,
	uint32_t addr_tlv, uint32_t mask_tlv, const struct addr *a);

void tlv_packet_free(struct tlv_packet *p);

/*
 * TLV Handler
 */
struct tlv_handler_ctx {
	const char *method;
	const char *id;
	struct tlv_packet *req;
	struct tlv_dispatcher *td;
	void *arg;
};

typedef struct tlv_packet *(*tlv_handler_cb)(struct tlv_handler_ctx *);

void tlv_handler_ctx_free(struct tlv_handler_ctx *ctx);

struct tlv_packet * tlv_packet_add_result(struct tlv_packet *p, int rc);

struct tlv_packet * tlv_packet_response(struct tlv_handler_ctx *ctx);

struct tlv_packet * tlv_packet_response_result(struct tlv_handler_ctx *ctx, int rc);

/*
 * TLV Dispatcher
 */
typedef void (*tlv_response_cb)(struct tlv_dispatcher *td, void *arg);

struct tlv_dispatcher;

struct tlv_dispatcher * tlv_dispatcher_new(tlv_response_cb cb, void *cb_arg);

int tlv_dispatcher_process_request(struct tlv_dispatcher *td, struct tlv_packet *p);

int tlv_dispatcher_add_handler(struct tlv_dispatcher *td,
		const char *method, tlv_handler_cb cb, void *arg);

int tlv_dispatcher_enqueue_response(struct tlv_dispatcher *td, struct tlv_packet *p);

void * tlv_dispatcher_dequeue_response(struct tlv_dispatcher *td, size_t *len);

void tlv_dispatcher_iter_extension_methods(struct tlv_dispatcher *td,
		const char *extension,
		void (*cb)(const char *method, void *arg), void *arg);

void tlv_dispatcher_free(struct tlv_dispatcher *td);

/*
 * APIs
 */
struct mettle;

void tlv_register_coreapi(struct mettle *m, struct tlv_dispatcher *td);

void tlv_register_stdapi(struct mettle *m, struct tlv_dispatcher *td);

#endif
