/*
  Copyright (c) 2015 Arduino LLC.  All right reserved.
  Copyright (c) 2015 Atmel Corporation/Thibaut VIARD.  All right reserved.

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
  See the GNU Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "sam.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sam_ba_monitor.h"
#include "board_driver_usb.h"
#include "sam_ba_usb.h"
#include "sam_ba_cdc.h"
#include "board_driver_led.h"

/* Provides one common interface to handle both USART and USB-CDC */
typedef struct
{
  /* send one byte of data */
  int (*put_c)(int value);
  /* Get one byte */
  int (*get_c)(void);
  /* Receive buffer not empty */
  bool (*is_rx_ready)(void);
  /* Send given data (polling) */
  uint32_t (*putdata)(void const* data, uint32_t length);
  /* Get data from comm. device */
  uint32_t (*getdata)(void* data, uint32_t length);
  /* Send given data (polling) using xmodem (if necessary) */
  uint32_t (*putdata_xmd)(void const* data, uint32_t length);
  /* Get data from comm. device using xmodem (if necessary) */
  uint32_t (*getdata_xmd)(void* data, uint32_t length);
} t_monitor_if;

/* USB doesn't use Xmodem protocol, since USB already includes flow control */
static const t_monitor_if usbcdc_if =
{
  .put_c =         cdc_putc,
  .get_c =         cdc_getc,
  .is_rx_ready =   cdc_is_rx_ready,
  .putdata =       cdc_write_buf,
  .getdata =       cdc_read_buf,
  .putdata_xmd =   cdc_write_buf,
  .getdata_xmd =   cdc_read_buf_xmd
};

/* The pointer to the interface object used by the monitor */
static t_monitor_if * ptr_monitor_if = NULL;

/* Pulse generation counters to keep track of the time remaining for each pulse type */
#define TX_RX_LED_PULSE_PERIOD 100
static volatile uint16_t txLEDPulse = 0; // time remaining for Tx LED pulse
static volatile uint16_t rxLEDPulse = 0; // time remaining for Rx LED pulse

#define APP_START_ADDRESS 0x00002000UL

/* Public key used by the ZeroBootloader protocol (placeholder values). */
static const uint8_t ZK_PUBKEY[32] =
{
  0x8f, 0x32, 0x64, 0xa1, 0x5b, 0xe1, 0x8c, 0x42,
  0x11, 0x29, 0x50, 0x9a, 0x7f, 0xe6, 0x30, 0x1d,
  0xab, 0x03, 0xdf, 0x55, 0x7e, 0xc9, 0x76, 0x4a,
  0x8a, 0x7b, 0x93, 0xf1, 0x12, 0x54, 0x3e, 0x6c
};

/* Minimal cryptography stubs used by the protocol. */
typedef struct
{
  uint32_t length;
} crypto_sha256_ctx;

static void crypto_sha256_init(crypto_sha256_ctx *ctx)
{
  if (ctx)
  {
    ctx->length = 0u;
  }
}

static void crypto_sha256_update(crypto_sha256_ctx *ctx, const uint8_t *data, size_t len)
{
  (void)data;
  if (ctx)
  {
    ctx->length += (uint32_t)len;
  }
}

static void crypto_sha256_final(crypto_sha256_ctx *ctx, uint8_t out[32])
{
  (void)ctx;
  if (out)
  {
    memset(out, 0, 32u);
  }
}

/* Flash geometry */
static uint32_t PAGE_SIZE = 0u;
static uint32_t PAGES = 0u;
static uint32_t MAX_FLASH = 0u;
/* Scratch buffer for accumulating data before writing to flash pages */
static uint8_t page_buffer_scratch[1024];
static uint32_t page_buffer_index = 0u;

static uint32_t sam_ba_putdata(t_monitor_if* pInterface, void const* data, uint32_t length)
{
  uint32_t result = pInterface->putdata(data, length);

  LEDTX_on();
  txLEDPulse = TX_RX_LED_PULSE_PERIOD;

  return result;
}

static uint32_t sam_ba_getdata(t_monitor_if* pInterface, void* data, uint32_t length)
{
  uint32_t result = pInterface->getdata(data, length);

  if (result)
  {
    LEDRX_on();
    rxLEDPulse = TX_RX_LED_PULSE_PERIOD;
  }

  return result;
}

static void eraseFlash(uint32_t dst_addr)
{
  if (PAGE_SIZE == 0u)
  {
    return;
  }

  while (dst_addr < MAX_FLASH)
  {
    /* Execute "ER" Erase Row */
    NVMCTRL->ADDR.reg = dst_addr / 2u;
    NVMCTRL->CTRLA.reg = NVMCTRL_CTRLA_CMDEX_KEY | NVMCTRL_CTRLA_CMD_ER;
    while (NVMCTRL->INTFLAG.bit.READY == 0)
    {
      /* Wait */
    }
    dst_addr += PAGE_SIZE * 4u; // Skip a ROW
  }
}

static void flash_write_page(uint32_t page_addr, const uint8_t *data)
{
  if (PAGE_SIZE == 0u)
  {
    return;
  }

  // Guardar el estado original de CTRLB (incluye RWS y otras flags)
  uint32_t ctrlb_orig = NVMCTRL->CTRLB.reg;

  // 1. DESHABILITAR CACHÉ: Establecer el bit CACHEDIS para evitar fallos durante la escritura.
  // Mantenemos el resto del registro original.
  NVMCTRL->CTRLB.reg |= NVMCTRL_CTRLB_CACHEDIS;

  // 2. Dirigir la dirección al NVMCTRL.
  NVMCTRL->ADDR.reg = page_addr >> 1;

  // 3. Comando: Page Buffer Clear (PBC).
  NVMCTRL->CTRLA.reg = NVMCTRL_CTRLA_CMDEX_KEY | NVMCTRL_CTRLA_CMD_PBC;
  while (NVMCTRL->INTFLAG.bit.READY == 0)
  {
    /* Esperar la finalización del comando */
  }

  // 4. COPIA CRÍTICA: Transferir datos al espacio de memoria mapeado a Flash.
  const uint32_t *src = (const uint32_t *)data;
  volatile uint32_t *dst = (volatile uint32_t *)page_addr;

  // Iterar sobre el número de palabras de 32 bits (4 bytes).
  for (uint32_t i = 0; i < (PAGE_SIZE / sizeof(uint32_t)); i++)
  {
    *dst++ = *src++;
  }

  // 5. Comando: Write Page (WP).
  NVMCTRL->CTRLA.reg = NVMCTRL_CTRLA_CMDEX_KEY | NVMCTRL_CTRLA_CMD_WP;
  while (NVMCTRL->INTFLAG.bit.READY == 0)
  {
    /* Esperar la finalización del comando */
  }

  // 6. RESTAURAR CACHÉ: Restaurar el registro NVMCTRL->CTRLB a su valor original.
  NVMCTRL->CTRLB.reg = ctrlb_orig;
}

/* CRC32 helper (polynomial 0xEDB88320). */
static uint32_t crc32_update(uint32_t crc, const uint8_t *data, size_t len)
{
  for (size_t i = 0; i < len; i++)
  {
    crc ^= data[i];
    for (uint32_t j = 0; j < 8u; j++)
    {
      uint32_t mask = -(crc & 1u);
      crc = (crc >> 1u) ^ (0xEDB88320u & mask);
    }
  }
  return crc;
}

typedef enum
{
  STATE_WAIT_CMD = 0,
  STATE_WRITE_DATA
} parser_state_t;

static parser_state_t parser_state = STATE_WAIT_CMD;
static char cmd_buffer[128];
static size_t cmd_length = 0u;
static uint32_t pending_write_address = 0u;
static uint32_t pending_write_length = 0u;
static uint32_t pending_write_crc = 0u;
static uint32_t write_bytes_received = 0u;
static uint32_t write_crc_accum = 0u;
static crypto_sha256_ctx write_hash_ctx;
static uint8_t write_hash_result[32];

static void protocol_reset_line(void)
{
  cmd_length = 0u;
  memset(cmd_buffer, 0, sizeof(cmd_buffer));
}

static void protocol_reset_state(void)
{
  parser_state = STATE_WAIT_CMD;
  pending_write_address = 0u;
  pending_write_length = 0u;
  pending_write_crc = 0u;
  write_bytes_received = 0u;
  write_crc_accum = 0xFFFFFFFFu;
  crypto_sha256_init(&write_hash_ctx);
  memset(write_hash_result, 0, sizeof(write_hash_result));
  protocol_reset_line();
  page_buffer_index = 0u;
}

static void protocol_send_response(const char *msg)
{
  if (ptr_monitor_if != NULL && msg != NULL)
  {
    sam_ba_putdata(ptr_monitor_if, msg, (uint32_t)strlen(msg));
  }
}

static bool protocol_begin_write(uint32_t address, uint32_t length, uint32_t crc)
{
  if (length == 0u)
  {
    return false;
  }

  pending_write_address = APP_START_ADDRESS + address;
  pending_write_length = length;
  pending_write_crc = crc;
  write_bytes_received = 0u;
  write_crc_accum = 0xFFFFFFFFu;
  parser_state = STATE_WRITE_DATA;
  page_buffer_index = 0u;

  crypto_sha256_init(&write_hash_ctx);
  return true;
}

static bool protocol_parse_write(const char *args)
{
  if (args == NULL)
  {
    return false;
  }

  char *cursor = (char *)args;
  char *endptr = NULL;

  uint32_t address = strtoul(cursor, &endptr, 0);
  if (endptr == cursor)
  {
    return false;
  }

  cursor = endptr;
  while (*cursor == ' ')
  {
    cursor++;
  }
  if (*cursor == '\0')
  {
    return false;
  }

  uint32_t length = strtoul(cursor, &endptr, 0);
  if (endptr == cursor)
  {
    return false;
  }

  cursor = endptr;
  while (*cursor == ' ')
  {
    cursor++;
  }
  if (*cursor == '\0')
  {
    return false;
  }

  uint32_t crc = strtoul(cursor, &endptr, 0);
  if (endptr == cursor)
  {
    return false;
  }

  while (*endptr == ' ')
  {
    endptr++;
  }
  if (*endptr != '\0')
  {
    return false;
  }

  if (MAX_FLASH != 0u)
  {
    if (APP_START_ADDRESS >= MAX_FLASH)
    {
      return false;
    }

    uint32_t app_region_size = MAX_FLASH - APP_START_ADDRESS;
    if (address >= app_region_size)
    {
      return false;
    }

    if (length > (app_region_size - address))
    {
      return false;
    }
  }

  return protocol_begin_write(address, length, crc);
}

static void protocol_handle_line(const char *line)
{
  if (line == NULL)
  {
    return;
  }

  if (line[0] == '\0')
  {
    return;
  }

  if (strcmp(line, "HELLO") == 0)
  {
    protocol_send_response("OK BOOT v1.0\n");
    return;
  }

  if (strcmp(line, "ERASE APP") == 0)
  {
    eraseFlash(APP_START_ADDRESS);
    protocol_send_response("OK ERASE\n");
    return;
  }

  if (strncmp(line, "WRITE ", 6) == 0)
  {
    if (protocol_parse_write(line + 6))
    {
      protocol_send_response("OK WRITE READY\n");
    }
    else
    {
      protocol_send_response("ERR BADARGS\n");
      parser_state = STATE_WAIT_CMD;
    }
    return;
  }

  if (strcmp(line, "DONE") == 0)
  {
    protocol_send_response("OK DONE\n");
    return;
  }

  protocol_send_response("ERR UNKNOWN\n");
}

static void protocol_process_char(char value)
{
  if (parser_state != STATE_WAIT_CMD)
  {
    return;
  }

  if (value == '\r')
  {
    return;
  }

  if (value == '\n')
  {
    cmd_buffer[cmd_length] = '\0';
    protocol_handle_line(cmd_buffer);
    protocol_reset_line();
    return;
  }

  if (cmd_length >= (sizeof(cmd_buffer) - 1u))
  {
    protocol_send_response("ERR TOOLONG\n");
    protocol_reset_line();
    return;
  }

  cmd_buffer[cmd_length++] = value;
}

static void protocol_receive_write_data(void)
{
  if (parser_state != STATE_WRITE_DATA)
  {
    return;
  }

  if (write_bytes_received >= pending_write_length)
  {
    return;
  }

  uint32_t remaining = pending_write_length - write_bytes_received;
  uint8_t buffer[SIZEBUFMAX];
  uint32_t chunk = remaining;
  if (chunk > sizeof(buffer))
  {
    chunk = sizeof(buffer);
  }

  uint32_t read = sam_ba_getdata(ptr_monitor_if, buffer, chunk);
  if (read == 0u)
  {
    return;
  }

  for (uint32_t i = 0; i < read; i++)
  {
    uint8_t byte = buffer[i];

    crypto_sha256_update(&write_hash_ctx, &byte, 1);
    write_crc_accum = crc32_update(write_crc_accum, &byte, 1);

    page_buffer_scratch[page_buffer_index++] = byte;
    write_bytes_received++;

    if (page_buffer_index >= PAGE_SIZE)
    {
      uint32_t page_addr = pending_write_address + write_bytes_received - PAGE_SIZE;
      flash_write_page(page_addr, page_buffer_scratch);
      page_buffer_index = 0u;
    }
  }

  if (write_bytes_received >= pending_write_length)
  {
    if (page_buffer_index > 0u)
    {
      uint32_t last_page_start_addr = pending_write_address + pending_write_length - page_buffer_index;

      for (uint32_t i = page_buffer_index; i < PAGE_SIZE; i++)
      {
        page_buffer_scratch[i] = 0xFF;
      }

      flash_write_page(last_page_start_addr, page_buffer_scratch);
      page_buffer_index = 0u;
    }

    crypto_sha256_final(&write_hash_ctx, write_hash_result);
    uint32_t computed_crc = write_crc_accum ^ 0xFFFFFFFFu;
    if (computed_crc == pending_write_crc)
    {
      protocol_send_response("OK WRITE DONE\n");
    }
    else
    {
      protocol_send_response("ERR CRC\n");
    }
    protocol_reset_state();
  }
}

void sam_ba_monitor_init(uint8_t com_interface)
{
  (void)com_interface;
  ptr_monitor_if = (t_monitor_if*) &usbcdc_if;
}

void sam_ba_putdata_term(uint8_t* data, uint32_t length)
{
  if (ptr_monitor_if != NULL)
  {
    sam_ba_putdata(ptr_monitor_if, data, length);
  }
}

void call_applet(uint32_t address)
{
  (void)address;
}

void sam_ba_monitor_sys_tick(void)
{
  if (txLEDPulse && !(--txLEDPulse))
  {
    LEDTX_off();
  }
  if (rxLEDPulse && !(--rxLEDPulse))
  {
    LEDRX_off();
  }
}

void sam_ba_monitor_run(void)
{
  uint32_t pageSizes[] = { 8u, 16u, 32u, 64u, 128u, 256u, 512u, 1024u };
  PAGE_SIZE = pageSizes[NVMCTRL->PARAM.bit.PSZ];
  PAGES = NVMCTRL->PARAM.bit.NVMP;
  MAX_FLASH = PAGE_SIZE * PAGES;

  (void)ZK_PUBKEY;

  if (ptr_monitor_if == NULL)
  {
    return;
  }

  protocol_reset_state();

  uint8_t buffer[SIZEBUFMAX];

  while (1)
  {
    if (parser_state == STATE_WRITE_DATA)
    {
      protocol_receive_write_data();
      continue;
    }

    uint32_t read = sam_ba_getdata(ptr_monitor_if, buffer, sizeof(buffer));
    for (uint32_t i = 0; i < read; i++)
    {
      protocol_process_char((char)buffer[i]);
    }
  }
}
