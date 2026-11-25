//go:build darwin && cgo

package ui

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>

static void lighthouseSetMacOSDockIcon(const void *bytes, int length) {
	@autoreleasepool {
		NSData *data = [NSData dataWithBytes:bytes length:(NSUInteger)length];
		NSImage *img = [[NSImage alloc] initWithData:data];
		if (img != nil) {
			dispatch_async(dispatch_get_main_queue(), ^{
				[[NSApplication sharedApplication] setApplicationIconImage:img];
			});
		}
	}
}
*/
import "C"

import "unsafe"

func applyPlatformIcon(pngBytes []byte) {
	if len(pngBytes) == 0 {
		return
	}
	C.lighthouseSetMacOSDockIcon(unsafe.Pointer(&pngBytes[0]), C.int(len(pngBytes)))
}
