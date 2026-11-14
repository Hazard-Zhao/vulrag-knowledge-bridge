#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- types & stubs (defined before the verbatim function copies) ---- */
struct usb_endpoint_descriptor {
	unsigned char bLength;
	unsigned char bDescriptorType;
};
struct usb_host_endpoint {
	struct usb_endpoint_descriptor desc;
};
struct device { int dummy; };

#define EP_ARRAY 16
struct usb_device {
	struct usb_host_endpoint *ep_in[EP_ARRAY];
	struct usb_host_endpoint *canary_in[112];   /* ep_in[16..127] land here */
	struct usb_host_endpoint *ep_out[EP_ARRAY];
	struct usb_host_endpoint *canary_out[112];  /* ep_out[16..127] land here */
	struct device dev;
};
struct stub_device { struct usb_device *udev; };

#define USBIP_DIR_IN  1
#define USBIP_DIR_OUT 0

#define usb_sndctrlpipe(d, e) 0x1000
#define usb_rcvctrlpipe(d, e) 0x2000
#define usb_sndbulkpipe(d, e) 0x3000
#define usb_rcvbulkpipe(d, e) 0x4000
#define usb_sndintpipe(d, e)  0x5000
#define usb_rcvintpipe(d, e)  0x6000
#define usb_sndisocpipe(d, e) 0x7000
#define usb_rcvisocpipe(d, e) 0x8000

static unsigned char observed_type = 0;   /* bDescriptorType of the endpoint the function read */
static int usb_endpoint_xfer_control(struct usb_endpoint_descriptor *epd) { observed_type = epd->bDescriptorType; return 0; }
static int usb_endpoint_xfer_bulk(struct usb_endpoint_descriptor *epd) { observed_type = epd->bDescriptorType; return 0; }
static int usb_endpoint_xfer_int(struct usb_endpoint_descriptor *epd) { observed_type = epd->bDescriptorType; return 0; }
static int usb_endpoint_xfer_isoc(struct usb_endpoint_descriptor *epd) { observed_type = epd->bDescriptorType; return 0; }

static void dev_err(struct device *dev, const char *fmt, ...) { (void)dev; (void)fmt; }

#define BUG() do { /* not reached in this harness */ } while (0)

#include "before.c"
#include "after.c"
#include "ineffective.c"
#include "equivalent.c"

int main(int argc, char **argv) {
	if (argc != 3) {
		fprintf(stderr, "usage: %s <variant:before|after|ineffective-01|equivalent-01> <epnum>\n", argv[0]);
		return 2;
	}
	const char *variant = argv[1];
	int epnum = atoi(argv[2]);

	int (*fn)(struct stub_device *, int, int) = NULL;
	if (strcmp(variant, "before") == 0) fn = get_pipe_before;
	else if (strcmp(variant, "after") == 0) fn = get_pipe_after;
	else if (strcmp(variant, "ineffective-01") == 0) fn = get_pipe_ineffective;
	else if (strcmp(variant, "equivalent-01") == 0) fn = get_pipe_equivalent;
	else { fprintf(stderr, "unknown variant: %s\n", variant); return 2; }

	struct usb_host_endpoint fake_eps[EP_ARRAY];
	struct usb_host_endpoint fake_oob_ep;
	struct usb_device udev;
	struct stub_device sdev;

	memset(&udev, 0, sizeof(udev));
	memset(fake_eps, 0, sizeof(fake_eps));
	memset(&fake_oob_ep, 0, sizeof(fake_oob_ep));

	for (int i = 0; i < EP_ARRAY; i++) {
		fake_eps[i].desc.bDescriptorType = 0xA1;   /* valid endpoint marker */
		udev.ep_in[i] = &fake_eps[i];
		udev.ep_out[i] = &fake_eps[i];
	}
	fake_oob_ep.desc.bDescriptorType = 0xB2;       /* OOB endpoint marker */
	for (int i = 0; i < 112; i++) {
		udev.canary_in[i] = &fake_oob_ep;
		udev.canary_out[i] = &fake_oob_ep;
	}
	sdev.udev = &udev;

	observed_type = 0;
	int ret = fn(&sdev, epnum, USBIP_DIR_IN);

	int read_oob = (observed_type == 0xB2);
	int read_valid = (observed_type == 0xA1);

	printf("VARIANT=%s EPNUM=%d RET=%d OBS_TYPE=0x%02x READ_OOB=%d READ_VALID=%d\n",
	       variant, epnum, ret, observed_type, read_oob, read_valid);
	return 0;
}
