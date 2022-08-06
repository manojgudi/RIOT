/*
 * Copyright (C) 2022 Gunar Schorcht
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     cpu_esp32
 * @{
 *
 * @file
 * @brief       Default SDK configuration for the ESP32C3 SoC bootloader
 *
 * @author      Gunar Schorcht <gunar@schorcht.net>
 */

#ifndef SDKCONFIG_DEFAULT_ESP32C3_H
#define SDKCONFIG_DEFAULT_ESP32C3_H

#ifndef DOXYGEN

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CONFIG_ESP32C3_DEFAULT_CPU_FREQ_MHZ
#define CONFIG_ESP32C3_DEFAULT_CPU_FREQ_MHZ 160
#endif

#define CONFIG_BOOTLOADER_COMPILER_OPTIMIZATION_SIZE 1
#define CONFIG_BOOTLOADER_FLASH_XMC_SUPPORT 1
#define CONFIG_BOOTLOADER_OFFSET_IN_FLASH 0x0
#define CONFIG_BOOTLOADER_RESERVE_RTC_SIZE 0x0
#define CONFIG_BOOTLOADER_VDDSDIO_BOOST_1_9V 1
#define CONFIG_BOOTLOADER_WDT_ENABLE 1
#define CONFIG_BOOTLOADER_WDT_TIME_MS 9000

#define CONFIG_ESP_CONSOLE_SECONDARY_USB_SERIAL_JTAG 1
#define CONFIG_ESP_CONSOLE_UART 1
#define CONFIG_ESP_CONSOLE_UART_DEFAULT 1
#define CONFIG_ESP_CONSOLE_UART_NUM 0

#define CONFIG_CONSOLE_UART_NUM CONFIG_ESP_CONSOLE_UART_NUM
#define CONFIG_CONSOLE_UART_DEFAULT CONFIG_ESP_CONSOLE_UART_DEFAULT

#define CONFIG_EFUSE_MAX_BLK_LEN 192

#define CONFIG_ESP32C3_DEBUG_OCDAWARE 1
#define CONFIG_ESP32C3_REV_MIN 3

#define CONFIG_IDF_FIRMWARE_CHIP_ID 0x0005

#define CONFIG_LOG_DEFAULT_LEVEL 3
#define CONFIG_LOG_TIMESTAMP_SOURCE_RTOS 1

#define CONFIG_PARTITION_TABLE_OFFSET 0x8000
#define CONFIG_PARTITION_TABLE_MD5 1

#define CONFIG_SPI_FLASH_ROM_DRIVER_PATCH 1

#ifdef __cplusplus
}
#endif

#endif /* DOXYGEN */
#endif /* SDKCONFIG_DEFAULT_ESP32C3_H */
/** @} */
