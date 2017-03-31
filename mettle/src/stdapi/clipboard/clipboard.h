#ifndef _STDAPI_CLIPBOARD_H_
#define _STDAPI_CLIPBOARD_H_

#define TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT            (TLV_META_TYPE_GROUP    | (TLV_EXTENSIONS + 39))
#define TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT_CONTENT    (TLV_META_TYPE_STRING   | (TLV_EXTENSIONS + 40))

struct tlv_packet *extapi_clipboard_get_data(struct tlv_handler_ctx *ctx);
struct tlv_packet *extapi_clipboard_set_data(struct tlv_handler_ctx *ctx);

#endif
