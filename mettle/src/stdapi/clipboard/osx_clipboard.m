#import <AVFoundation/AVFoundation.h>

#import <AppKit/NSPasteboard.h>

#include "tlv.h"
#include "clipboard.h"

struct tlv_packet *extapi_clipboard_set_data(struct tlv_handler_ctx *ctx)
{
  const char* clipboard_text = tlv_packet_get_str(ctx->req, TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT_CONTENT);
  @autoreleasepool {
    NSString *text = [NSString stringWithUTF8String:clipboard_text];
    NSPasteboard *pasteboard = [NSPasteboard generalPasteboard];
    [pasteboard clearContents];
    [pasteboard setString:text forType:@"public.utf8-plain-text"];
  }
  return tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
}

struct tlv_packet *extapi_clipboard_get_data(struct tlv_handler_ctx *ctx)
{
  struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
  @autoreleasepool {
    NSPasteboard *pasteboard = [NSPasteboard generalPasteboard];
    NSString* text = [pasteboard stringForType:NSPasteboardTypeString];
    const char *clipboard_text = (const char *)[text cStringUsingEncoding:NSUTF8StringEncoding];

    struct tlv_packet *group = tlv_packet_new(TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT, 0);
    group = tlv_packet_add_str(group, TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT_CONTENT, clipboard_text);
    p = tlv_packet_add_child(p, group);
  }
  return p;
}
