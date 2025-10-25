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

#include <stdbool.h>
#include <stdio.h>
#include <sam.h>
#include "sam_ba_monitor.h"
#include "board_definitions.h"
#include "board_driver_i2c.h"
#include "board_driver_pmic.h"
#include "board_driver_jtag.h"
#include "sam_ba_usb.h"
#include "sam_ba_cdc.h"
#include "board_driver_led.h"
#include "signature_footer.h"
#include "crc32.h"

extern uint32_t __sketch_vectors_ptr; // Exported value from linker script
extern void board_init(void);

volatile uint32_t* pulSketch_Start_Address;

static void jump_to_application(void) {

  /* Rebase the Stack Pointer */
  __set_MSP( (uint32_t)(__sketch_vectors_ptr) );

  /* Rebase the vector table base address */
  SCB->VTOR = ((uint32_t)(&__sketch_vectors_ptr) & SCB_VTOR_TBLOFF_Msk);

  /* Jump to application Reset Handler in the application */
  asm("bx %0"::"r"(*pulSketch_Start_Address));
}

static volatile bool main_b_cdc_enable = false;

#ifdef CONFIGURE_PMIC
static volatile bool jump_to_app = false;
#endif

static inline const zk_footer_t* footer_ptr(void) {
  return (const zk_footer_t*)(FOOTER_ADDR);
}

static bool is_footer_valid_meta(const zk_footer_t *footer) {
  if (footer == NULL) {
    return false;
  }

  if (footer->magic != ZK_FOOTER_MAGIC) {
    return false;
  }

  if (footer->tail_magic != ZK_FOOTER_TAIL) {
    return false;
  }

  if (footer->version != 0x0001u) {
    return false;
  }

  if (footer->algo != SIG_ALGO_CRC32K) {
    return false;
  }

  if (footer->app_size == 0u || footer->app_size > APP_MAX_SIZE) {
    return false;
  }

  if ((APP_START_ADDR + footer->app_size) > FOOTER_ADDR) {
    return false;
  }

  return true;
}

static uint32_t compute_crc32_app_internal(uint32_t app_size, uint32_t *out_plain_crc) {
  const uint8_t *app = (const uint8_t *)APP_START_ADDR;
  uint32_t crc_plain = crc32_compute(app, app_size);

  if (out_plain_crc != NULL) {
    *out_plain_crc = crc_plain;
  }

  uint32_t key = ZK_CRC32K_KEY;
  return crc32_update(crc_plain, &key, sizeof(key));
}

static bool is_app_signed_ok(void) {
  const zk_footer_t *footer = footer_ptr();

  if (!is_footer_valid_meta(footer)) {
    return false;
  }

  uint32_t crc_plain = 0u;
  uint32_t expected_sig = compute_crc32_app_internal(footer->app_size, &crc_plain);

  if (crc_plain != footer->crc32_app) {
    return false;
  }

  return (expected_sig == footer->sig32);
}

static void busy_wait_ms(uint32_t ms) {
  if (ms == 0u) {
    return;
  }

  uint32_t iterations_per_ms = (CPU_FREQUENCY / 1000u) / 12u;
  if (iterations_per_ms == 0u) {
    iterations_per_ms = 1u;
  }
  uint32_t iterations = iterations_per_ms * ms;

  while (iterations-- > 0u) {
    __NOP();
  }
}

static void delay_with_blink_ms(uint32_t total_ms) {
  if (total_ms == 0u) {
    return;
  }

  LED_init();
  LED_off();

  const uint32_t step_ms = 100u;
  uint32_t remaining = total_ms;

  while (remaining > 0u) {
    LED_toggle();
    uint32_t chunk = (remaining < step_ms) ? remaining : step_ms;
    busy_wait_ms(chunk);
    remaining -= chunk;
  }

  LED_off();
}

static void perform_application_jump(bool delay_before_jump) {
  if (delay_before_jump) {
    delay_with_blink_ms(VERIFY_FAIL_DELAY_MS);
  }

#ifdef CONFIGURE_PMIC
  jump_to_app = true;
#else
  jump_to_application();
#endif
}

static void boot_decision_and_jump(void) {
  if (is_app_signed_ok()) {
    perform_application_jump(false);
  } else {
    perform_application_jump(true);
  }
}

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

  boot_decision_and_jump();

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
    jump_to_application();
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
