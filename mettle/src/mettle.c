/**
 * Copyright 2015 Rapid7
 * @brief mettle main object
 * @file mettle.c
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <eio.h>
#include <sigar.h>

#include "mettle.h"
#include "log.h"
#include "network_client.h"
#include "tlv.h"

struct mettle {
	struct channelmgr *cm;
	struct network_client *nc;
	bool first_packet;
	struct tlv_dispatcher *td;

	sigar_t *sigar;
	sigar_sys_info_t sysinfo;
	char *uuid;
	size_t uuid_len;
	char fqdn[SIGAR_MAXDOMAINNAMELEN];
	struct ev_loop *loop;
	struct ev_timer heartbeat;
};

static struct ev_idle eio_idle_watcher;
static struct ev_async eio_async_watcher;

static void
eio_idle_cb(struct ev_loop *loop, struct ev_idle *w, int revents)
{
	if (eio_poll() != -1) {
		ev_idle_stop(loop, w);
	}
}

static void
eio_async_cb(struct ev_loop *loop, struct ev_async *w, int revents)
{
	if (eio_poll() == -1) {
		ev_idle_start(loop, &eio_idle_watcher);
	}
	ev_async_start(ev_default_loop(EVFLAG_NOENV), &eio_async_watcher);
}

static void
eio_want_poll(void)
{
	ev_async_send(ev_default_loop(EVFLAG_NOENV), &eio_async_watcher);
}

static void
eio_done_poll(void)
{
	ev_async_stop(ev_default_loop(EVFLAG_NOENV), &eio_async_watcher);
}

static void
heartbeat_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
	log_info("Heartbeat");
}

int start_heartbeat(struct mettle *m)
{
	ev_timer_init(&m->heartbeat, heartbeat_cb, 0, 5.0);
	ev_timer_start(m->loop, &m->heartbeat);
	return 0;
}

int mettle_add_server_uri(struct mettle *m, const char *uri)
{
	return network_client_add_server(m->nc, uri);
}

int mettle_add_tcp_sock(struct mettle *m, int fd)
{
	return network_client_add_tcp_sock(m->nc, fd);
}

struct ev_loop * mettle_get_loop(struct mettle *m)
{
	return m->loop;
}

const char *mettle_get_fqdn(struct mettle *m)
{
	return m->fqdn;
}

const char *mettle_get_machine_id(struct mettle *m)
{
	return m->sysinfo.uuid;
}

int mettle_set_uuid(struct mettle *m, char *uuid, size_t len)
{
	free(m->uuid);
	m->uuid_len = 0;

	m->uuid = malloc(len);
	if (m->uuid == NULL)
		return -1;

	m->uuid_len = len;
	memcpy(m->uuid, uuid, len);
	return 0;
}

const char *mettle_get_uuid(struct mettle *m, size_t *len)
{
	*len = m->uuid_len;
	return m->uuid;
}

struct tlv_dispatcher *mettle_get_tlv_dispatcher(struct mettle *m)
{
	return m->td;
}

sigar_t *mettle_get_sigar(struct mettle *m)
{
	return m->sigar;
}

struct channelmgr * mettle_get_channelmgr(struct mettle *m)
{
	return m->cm;
}

void mettle_free(struct mettle *m)
{
	if (m) {
		channelmgr_free(m->cm);
		tlv_dispatcher_free(m->td);
		network_client_free(m->nc);
		free(m);
	}
}

static void on_tlv_response(struct tlv_dispatcher *td, void *arg)
{
	struct mettle *m = arg;
	void *buf;
	size_t len;

	while ((buf = tlv_dispatcher_dequeue_response(td, &len))) {
		network_client_write(m->nc, buf, len);
		free(buf);
	}
}

static void on_network_connect(struct network_client *nc, void *arg)
{
	struct mettle *m = arg;
	m->first_packet = true;
}

static void on_network_read(struct network_client *nc, void *arg)
{
	struct mettle *m = arg;
	struct buffer_queue *q = network_client_rx_queue(nc);
	struct tlv_packet *request;

	if (m->first_packet) {
		if (tlv_have_sync_packet(q, "core_machine_id")) {
			m->first_packet = false;
		} else {
			return;
		}
	}

	while ((request = tlv_packet_read_buffer_queue(q))) {
		tlv_dispatcher_process_request(m->td, request);
	}
}

struct mettle *mettle(void)
{
	struct mettle *m = calloc(1, sizeof(*m));

	if (m == NULL) {
		return NULL;
	}

	/*
	 * TODO: let libev choose the backend instead of demanding select. On Linux
	 * 2.6.22 we get the following with the epoll backend (compiled with much
	 * more recent headers):
	 *
	 * (libev) epoll_wait: Bad file descriptor
	 * Abort
	 */
	m->loop = ev_default_loop(EVFLAG_NOENV | EVBACKEND_SELECT);

	ev_idle_init(&eio_idle_watcher, eio_idle_cb);
	ev_async_init(&eio_async_watcher, eio_async_cb);
	eio_init(eio_want_poll, eio_done_poll);

	start_heartbeat(m);

	m->nc = network_client_new(m->loop);
	if (m->nc == NULL) {
		goto err;
	}

	if (sigar_open(&m->sigar) == -1) {
		goto err;
	}

	sigar_fqdn_get(m->sigar, m->fqdn, sizeof(m->fqdn));

	sigar_sys_info_get(m->sigar, &m->sysinfo);

	network_client_set_connect_cb(m->nc, on_network_connect, m);

	network_client_set_read_cb(m->nc, on_network_read, m);

	m->td = tlv_dispatcher_new(on_tlv_response, m);
	if (m->td == NULL) {
		goto err;
	}

	m->cm = channelmgr_new();
	if (m->cm == NULL) {
		goto err;
	}

	return m;

err:
	mettle_free(m);
	return NULL;
}

int mettle_start(struct mettle *m)
{
	tlv_register_coreapi(m);

	tlv_register_stdapi(m);

	network_client_start(m->nc);

	ev_async_start(m->loop, &eio_async_watcher);

	return ev_run(m->loop, 0);
}
