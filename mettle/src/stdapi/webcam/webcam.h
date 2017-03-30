#ifndef _STDAPI_WEBCAM_H_
#define _STDAPI_WEBCAM_H_

struct tlv_packet *webcam_list(struct tlv_handler_ctx *ctx);
struct tlv_packet *webcam_start(struct tlv_handler_ctx *ctx);
struct tlv_packet *webcam_stop(struct tlv_handler_ctx *ctx);
struct tlv_packet *webcam_get_frame(struct tlv_handler_ctx *ctx);

#endif
