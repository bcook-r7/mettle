/**
 * Copyright 2015 Rapid7
 * @brief Clipboard API
 * @file clipboard.c
 */

#include <endian.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include <mettle.h>

#include "channel.h"
#include "log.h"
#include "tlv.h"
#include "clipboard.h"

void clipboard_register_handlers(struct mettle *m)
{
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);

#if HAVE_CLIPBOARD
	tlv_dispatcher_add_handler(td, "extapi_clipboard_get_data", extapi_clipboard_get_data, m);
	tlv_dispatcher_add_handler(td, "extapi_clipboard_set_data", extapi_clipboard_set_data, m);
#endif
}

