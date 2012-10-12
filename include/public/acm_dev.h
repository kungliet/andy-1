#define UNRSV	0xFF

#ifdef CONFIG_MACHINE_IMX21

#define DEV_UNIT_ADDR_SHIFT	12
#define DEV_UNIT_ADDR_SIZE		(0x1<<DEV_UNIT_ADDR_SHIFT)

#define IMX21_AIPI1			0x0
#define IMX21_DMA 			0x1
#define IMX21_WDOG 			0x2
#define IMX21_GPT1 			0x3
#define IMX21_GPT2			0x4
#define IMX21_GPT3 			0x5
#define IMX21_PWM 			0x6
#define IMX21_RTC 			0x7
#define IMX21_KPP 			0x8
#define IMX21_OWIRE 			0x9
#define IMX21_UART1			0xA
#define IMX21_UART2			0xB
#define IMX21_UART3			0xC
#define IMX21_UART4			0xD
#define IMX21_CSPI1			0xE
#define IMX21_CSPI2			0xF
#define IMX21_SSI1			0x10
#define IMX21_SSI2			0x11
#define IMX21_I2C				0x12
#define IMX21_SDHC1 			0x13
#define IMX21_SDHC2			0x14
#define IMX21_GPIO			0x15
#define IMX21_AUDMUX			0x16
#define IMX21_CSPI3			0x17
#define IMX21_AIPI2			0x20
#define IMX21_LCD 			0x21
#define IMX21_SLCD			0x22
#define IMX21_USBOTG1		0x24
#define IMX21_USBOTG2		0x25
#define IMX21_eMMA 			0x26
#define IMX21_CRM  			0x27
#define IMX21_FIRI 			0x28 
#define IMX21_RNGA   		0x29
#define IMX21_RTIC			0x2A
#define IMX21_JAM   			0x3E 
#define IMX21_MAX     		0x3F
#define IMX21_CS1				0xCC
#define IMX21_CHIPSELECT	0xD1
#define IMX21_PCMCIA			0xD2
#define IMX21_NANDFC			0xD3
#define IMX21_FLASH_MEM		0x50

#else
/* Below is default */
#define DEV_UNIT_ADDR_SHIFT	12
#define DEV_UNIT_ADDR_SIZE		(0x1<<DEV_UNIT_ADDR_SHIFT)

#endif
