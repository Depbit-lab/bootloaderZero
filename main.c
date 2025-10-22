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

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sam.h>
#include "sam_ba_monitor.h"
#include "board_definitions.h"
#include "board_driver_i2c.h"
#include "board_driver_pmic.h"
#include "board_driver_jtag.h"
#include "sam_ba_usb.h"
#include "sam_ba_cdc.h"

#define FLASH_BASE      (0x00000000UL)
#define FLASH_SIZE      (0x00040000UL)   /* 256 KiB */
#define BOOTLOADER_SIZE (0x00002000UL)   /* 8 KiB Arduino Zero */
#define APP_START       (FLASH_BASE + BOOTLOADER_SIZE)

#define FOOTER_MAGIC    (0x5A4B5955UL)  /* 'ZKYU' */
#define FOOTER_VERSION  (0x0001)
#define FOOTER_SIZE     (64U)

typedef struct __attribute__((packed)) {
  uint32_t magic;
  uint16_t version;
  uint16_t flags;
  uint64_t seq;
  uint8_t  mac[32];
} fw_footer_t;

static inline uint32_t footer_addr(void) {
  return (FLASH_BASE + FLASH_SIZE - FOOTER_SIZE);
}

/* Clave placeholder: CAMBIAR EN PRODUCCIÓN */
static const uint8_t MASTER_SECRET[16] = {
  0x3A,0x92,0xC7,0x51,0x1D,0x60,0xE4,0xB9,
  0x08,0xAF,0x33,0xDE,0x74,0x21,0x5C,0xF0
};

static void derive_token16(uint8_t out16[16]) {
  for (int i = 0; i < 16; i++) {
    out16[i] = (uint8_t)(MASTER_SECRET[i] ^ 0xA5);
  }
}

extern void flash_read(uint32_t addr, void* dst, uint32_t len);
extern void delay_ms(uint32_t ms);
extern void jump_to_application(uint32_t app_start_addr);

extern uint32_t __sketch_vectors_ptr; // Exported value from linker script
extern void board_init(void);

volatile uint32_t* pulSketch_Start_Address;

static void do_jump_to_application(void) {

  /* Rebase the Stack Pointer */
  __set_MSP( (uint32_t)(__sketch_vectors_ptr) );

  /* Rebase the vector table base address */
  SCB->VTOR = ((uint32_t)(&__sketch_vectors_ptr) & SCB_VTOR_TBLOFF_Msk);

  /* Jump to application Reset Handler in the application */
  asm("bx %0"::"r"(*pulSketch_Start_Address));
}

void flash_read(uint32_t addr, void* dst, uint32_t len) {
  if (dst == NULL || len == 0) {
    return;
  }

  memcpy(dst, (const void *)addr, len);
}

void delay_ms(uint32_t ms) {
  while (ms--) {
    for (uint32_t i = 0; i < 1000; i++) {
      __asm__ __volatile__("nop");
    }
  }
}

void jump_to_application(uint32_t app_start_addr) {
  (void)app_start_addr;
  do_jump_to_application();
}

void check_mac_footer_and_boot(void) {
  fw_footer_t f;
  const uint32_t faddr = footer_addr();

  flash_read(faddr, &f, sizeof(f));

  uint8_t expected[16];
  derive_token16(expected);

  int valid = 0;
  if (f.magic == FOOTER_MAGIC && f.version == FOOTER_VERSION) {
    valid = (memcmp(f.mac, expected, 16) == 0);
  }

  if (!valid) {
    delay_ms(15000);
  }

  jump_to_application(APP_START);
}

static volatile bool main_b_cdc_enable = false;

#ifdef CONFIGURE_PMIC
static volatile bool jump_to_app = false;
#endif

/**
 * \brief Check the application startup condition
 *
 */
static void check_start_application(void)
{

  /*
   * Test sketch stack pointer @ &__sketch_vectors_ptr
   * Stay in SAM-BA if value @ (&__sketch_vectors_ptr) == 0xFFFFFFFF (Erased flash cell value)
   */
  if (__sketch_vectors_ptr == 0xFFFFFFFF)
  {
    /* Stay in bootloader */
    return;
  }

  /*
   * Load the sketch Reset Handler address
   * __sketch_vectors_ptr is exported from linker script and point on first 32b word of sketch vector table
   * First 32b word is sketch stack
   * Second 32b word is sketch entry point: Reset_Handler()
   */
  pulSketch_Start_Address = &__sketch_vectors_ptr ;
  pulSketch_Start_Address++ ;

  /*
   * Test vector table address of sketch @ &__sketch_vectors_ptr
   * Stay in SAM-BA if this function is not aligned enough, ie not valid
   */
  if ( ((uint32_t)(&__sketch_vectors_ptr) & ~SCB_VTOR_TBLOFF_Msk) != 0x00)
  {
    /* Stay in bootloader */
    return;
  }

#if defined(BOOT_DOUBLE_TAP_ADDRESS)
  #define DOUBLE_TAP_MAGIC 0x07738135
  if (PM->RCAUSE.bit.POR)
  {
    /* On power-on initialize double-tap */
    BOOT_DOUBLE_TAP_DATA = 0;
  }
  else
  {
    if (BOOT_DOUBLE_TAP_DATA == DOUBLE_TAP_MAGIC)
    {
      /* Second tap, stay in bootloader */
      BOOT_DOUBLE_TAP_DATA = 0;
      return;
    }

#ifdef HAS_EZ6301QI
    // wait a tiny bit for the EZ6301QI to settle,
    // as it's connected to RESETN and might reset
    // the chip when the cable is plugged in fresh

    for (uint32_t i=0; i<2500; i++) /* 10ms */
      /* force compiler to not optimize this... */
      __asm__ __volatile__("");
#endif

    /* First tap */
    BOOT_DOUBLE_TAP_DATA = DOUBLE_TAP_MAGIC;

    /* Wait 0.5sec to see if the user tap reset again.
     * The loop value is based on SAMD21 default 1MHz clock @ reset.
     */
    for (uint32_t i=0; i<125000; i++) /* 500ms */
      /* force compiler to not optimize this... */
      __asm__ __volatile__("");

    /* Timeout happened, continue boot... */
    BOOT_DOUBLE_TAP_DATA = 0;
  }
#endif

/*
#if defined(BOOT_LOAD_PIN)
  volatile PortGroup *boot_port = (volatile PortGroup *)(&(PORT->Group[BOOT_LOAD_PIN / 32]));
  volatile bool boot_en;

  // Enable the input mode in Boot GPIO Pin
  boot_port->DIRCLR.reg = BOOT_PIN_MASK;
  boot_port->PINCFG[BOOT_LOAD_PIN & 0x1F].reg = PORT_PINCFG_INEN | PORT_PINCFG_PULLEN;
  boot_port->OUTSET.reg = BOOT_PIN_MASK;
  // Read the BOOT_LOAD_PIN status
  boot_en = (boot_port->IN.reg) & BOOT_PIN_MASK;

  // Check the bootloader enable condition
  if (!boot_en)
  {
    // Stay in bootloader
    return;
  }
#endif
*/

#ifdef CONFIGURE_PMIC
  jump_to_app = true;
#else
  check_mac_footer_and_boot();
#endif

}

#if DEBUG_ENABLE
#	define DEBUG_PIN_HIGH 	port_pin_set_output_level(BOOT_LED, 1)
#	define DEBUG_PIN_LOW 	port_pin_set_output_level(BOOT_LED, 0)
#else
#	define DEBUG_PIN_HIGH 	do{}while(0)
#	define DEBUG_PIN_LOW 	do{}while(0)
#endif

/**
 *  \brief SAMD21 SAM-BA Main loop.
 *  \return Unused (ANSI-C compatibility).
 */
int main(void)
{
  P_USB_CDC pCdc;
  DEBUG_PIN_HIGH;

  /* Jump in application if condition is satisfied */
  check_start_application();

  /* We have determined we should stay in the monitor. */
  /* System initialization */
  board_init();
  __enable_irq();

#ifdef CONFIGURE_PMIC
  configure_pmic();
#endif

#ifdef ENABLE_JTAG_LOAD
  uint32_t temp ;
  // Get whole current setup for both odd and even pins and remove odd one
  temp = (PORT->Group[0].PMUX[27 >> 1].reg) & PORT_PMUX_PMUXE( 0xF ) ;
  // Set new muxing
  PORT->Group[0].PMUX[27 >> 1].reg = temp|PORT_PMUX_PMUXO( 7 ) ;
  // Enable port mux
  PORT->Group[0].PINCFG[27].reg |= PORT_PINCFG_PMUXEN ;
  clockout(0, 1);

  jtagInit();
  if ((jtagBitstreamVersion() & 0xFF000000) != 0xB0000000) {
    // FPGA is not in the bootloader, restart it
    jtagReload();    
  }
#endif

#ifdef CONFIGURE_PMIC
  if (jump_to_app == true) {
    check_mac_footer_and_boot();
  }
#endif

  pCdc = usb_init();

  DEBUG_PIN_LOW;

  /* Start the sys tick (1 ms) */
  SysTick_Config(1000);

  /* Wait for a complete enum on usb or a '#' char on serial line */
  while (1)
  {
    if (pCdc->IsConfigured(pCdc) != 0)
    {
      main_b_cdc_enable = true;
    }

    /* Check if a USB enumeration has succeeded and if comm port has been opened */
    if (main_b_cdc_enable)
    {
      sam_ba_monitor_init(SAM_BA_INTERFACE_USBCDC);
      /* SAM-BA on USB loop */
      while( 1 )
      {
        sam_ba_monitor_run();
      }
    }
  }
}

void SysTick_Handler(void)
{
  sam_ba_monitor_sys_tick();
}
