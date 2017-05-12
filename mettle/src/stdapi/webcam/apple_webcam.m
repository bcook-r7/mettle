#import <AVFoundation/AVFoundation.h>

#if TARGET_OS_IPHONE
#import <UIKit/UIImage.h>
#else
#import <AppKit/NSImage.h>
#endif

#include "tlv.h"
#include "webcam.h"

#define TLV_TYPE_WEBCAM_IMAGE          (TLV_META_TYPE_RAW     | TLV_EXTENSIONS + 1)
#define TLV_TYPE_WEBCAM_INTERFACE_ID   (TLV_META_TYPE_UINT    | TLV_EXTENSIONS + 2)
#define TLV_TYPE_WEBCAM_QUALITY        (TLV_META_TYPE_UINT    | TLV_EXTENSIONS + 3)
#define TLV_TYPE_WEBCAM_NAME           (TLV_META_TYPE_STRING  | TLV_EXTENSIONS + 4)

@interface Capture : NSObject <AVCaptureVideoDataOutputSampleBufferDelegate>
- (void) captureOutput: (AVCaptureOutput*) output
  didOutputSampleBuffer: (CMSampleBufferRef) buffer
         fromConnection: (AVCaptureConnection*) connection;
@end
@interface Capture ()
{
  CVImageBufferRef head;
  AVCaptureSession* session;
  int count;
}
- (BOOL) start: (int) deviceIndex;
- (void) stop;
- (NSData *) getFrame;
@end

@implementation Capture

- (id) init
{
  self = [super init];
  head = nil;
  count = 0;
  return self;
}

- (void) dealloc
{
  @synchronized (self) {
    if (head != nil) {
      CFRelease(head);
    }
  }
}

- (BOOL) start: (int) deviceIndex
{
  session = [[AVCaptureSession alloc] init];
  session.sessionPreset = AVCaptureSessionPresetMedium;

  NSArray *devices = [AVCaptureDevice devicesWithMediaType:AVMediaTypeVideo];
  AVCaptureDevice *device = devices[deviceIndex - 1];

  NSError* error = nil;
  AVCaptureDeviceInput* input =
    [AVCaptureDeviceInput deviceInputWithDevice: device  error: &error];
  [session addInput:input];

  AVCaptureVideoDataOutput *output = [[AVCaptureVideoDataOutput alloc] init];
  [session addOutput:output];

  dispatch_queue_t queue = dispatch_queue_create("webcam_queue", NULL);
  [output setSampleBufferDelegate:self queue:queue];

  [session startRunning];
  return true;
}

- (void) stop
{
  [session stopRunning];
}

- (NSData* ) getFrame
{
  //Wait for 5 seconds or for 5 frames otherwise the frame is too dark
  for (int waitFrame = 0; waitFrame < 500; waitFrame++) {
    if (count > 5) {
      break;
    }
    usleep(10000);
  }
  @synchronized (self) {
    if (head == nil) {
      return nil;
    }
#if TARGET_OS_IPHONE
    CIImage *ciImage = [[CIImage imageWithCVPixelBuffer:head] imageByApplyingOrientation:6];
    CIContext *temporaryContext = [CIContext contextWithOptions:nil];
    CGImageRef videoImage = [temporaryContext
      createCGImage:ciImage
           fromRect:CGRectMake(0, 0,
               CVPixelBufferGetHeight(head),
               CVPixelBufferGetWidth(head))];
    UIImage *uiImage = [[UIImage alloc] initWithCGImage:videoImage];
    NSData* frame = UIImageJPEGRepresentation(uiImage, 1.0);
    CGImageRelease(videoImage);
    return frame;
#else
    CIImage* ciImage = [CIImage imageWithCVImageBuffer: head];
    NSBitmapImageRep* bitmapRep = [[NSBitmapImageRep alloc] initWithCIImage: ciImage];
    NSDictionary *props = [NSDictionary dictionary];
    return [bitmapRep representationUsingType:NSJPEGFileType properties: props];
#endif
  }
  return nil;
}

- (void) captureOutput: (AVCaptureOutput*) output
  didOutputSampleBuffer: (CMSampleBufferRef) buffer
         fromConnection: (AVCaptureConnection*) connection
{
  CVImageBufferRef frame = CMSampleBufferGetImageBuffer(buffer);
  CVImageBufferRef prev;
  CFRetain(frame);
  @synchronized (self) {
    prev = head;
    head = frame;
    count++;
  }
  if (prev != nil) {
    CFRelease(prev);
  }
}
@end

Capture* capture;

struct tlv_packet *webcam_get_frame(struct tlv_handler_ctx *ctx)
{
  struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
  @autoreleasepool {
    NSData* jpgData = [capture getFrame];
    if (jpgData) {
      p = tlv_packet_add_raw(p, TLV_TYPE_WEBCAM_IMAGE, jpgData.bytes, jpgData.length);
    }
  }
  return p;
}

struct tlv_packet *webcam_start(struct tlv_handler_ctx *ctx)
{
  uint32_t deviceIndex = 0;
  uint32_t quality = 0;
  tlv_packet_get_u32(ctx->req, TLV_TYPE_WEBCAM_INTERFACE_ID, &deviceIndex);
  tlv_packet_get_u32(ctx->req, TLV_TYPE_WEBCAM_QUALITY, &quality);

  int rc = TLV_RESULT_FAILURE;
  @autoreleasepool {
    capture = [[Capture alloc] init];
    if ([capture start:deviceIndex]) {
      rc = TLV_RESULT_SUCCESS;
    } else {
      capture = nil;
    }
  }
  return tlv_packet_response_result(ctx, rc);
}

struct tlv_packet *webcam_stop(struct tlv_handler_ctx *ctx)
{
  @autoreleasepool {
    [capture stop];
  }
  return tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
}

struct tlv_packet *webcam_list(struct tlv_handler_ctx *ctx)
{
  struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
  NSArray *devices = [AVCaptureDevice devicesWithMediaType:AVMediaTypeVideo];
  for (AVCaptureDevice *device in devices) {
    const char *webcam_str = (const char *)[[device localizedName]cStringUsingEncoding:NSUTF8StringEncoding];
    p = tlv_packet_add_str(p, TLV_TYPE_WEBCAM_NAME, webcam_str);
  }
  return p;
}
