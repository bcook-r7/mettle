/**
 * Copyright 2015 Rapid7
 * @brief Core API calls
 * @file stdapi.c
 */

#include "mettle.h"
#include "fs/file.c"
#include "net/client.c"
#include "net/config.c"
#include "net/server.c"
#include "net/resolve.c"
#include "sys/config.c"
#include "sys/process.c"
#include "webcam/webcam.c"
#include "ui/ui.c"
#include "clipboard/clipboard.c"

void tlv_register_stdapi(struct mettle *m)
{
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);

	file_register_handlers(m);

	net_client_register_handlers(m);
	net_server_register_handlers(m);
	net_config_register_handlers(m);
	net_resolve_register_handlers(m);

	sys_config_register_handlers(m);
	sys_process_register_handlers(m);

	webcam_register_handlers(m);
	ui_register_handlers(m);
	clipboard_register_handlers(m);
}
