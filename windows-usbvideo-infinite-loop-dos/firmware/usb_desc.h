#ifndef _usb_desc_h_
#define _usb_desc_h_

#include <stdint.h>
#include <stddef.h>

#define ENDPOINT_UNUSED                 0x00

#define VENDOR_ID               0x1209
#define PRODUCT_ID              0x0003
#define BCD_DEVICE              0x0300

#define DEVICE_CLASS            0x0E
#define DEVICE_SUBCLASS         0x01
#define DEVICE_PROTOCOL         0x00

#define MANUFACTURER_NAME       {'C','V','E',' ','L','a','b'}
#define MANUFACTURER_NAME_LEN   7
#define PRODUCT_NAME            {'U','V','C','D','o','S','1','2'}
#define PRODUCT_NAME_LEN        8

#define EP0_SIZE                64
#define NUM_ENDPOINTS           0
#define NUM_USB_BUFFERS         4
#define NUM_INTERFACE           1

extern volatile uint8_t usb_alt_setting;
extern const uint8_t usb_endpoint_config_table[1];

typedef struct {
    uint16_t        wValue;
    uint16_t        wIndex;
    const uint8_t   *addr;
    uint16_t        length;
} usb_descriptor_list_t;

extern const usb_descriptor_list_t usb_descriptor_list[];

struct usb_string_descriptor_struct {
    uint8_t  bLength;
    uint8_t  bDescriptorType;
    uint16_t wString[];
};

#endif
