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
#include <string.h>
#include <sam.h>
#include "sam_ba_monitor.h"
#include "board_definitions.h"
#include "board_driver_i2c.h"
#include "board_driver_pmic.h"
#include "board_driver_jtag.h"
#include "sam_ba_usb.h"
#include "sam_ba_cdc.h"
#include "zk_fw_footer.h"
#include "zk_secret.h"
#include "zk_blake2s_mac.h"

#define SRAM_START 0x20000000u
#define SRAM_END   0x20008000u
#define PENALTY_DELAY_MS 15000u

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

static uint32_t dsu_crc32_aligned(uint32_t seed, const void *data, size_t len)
{
  if (len == 0u)
  {
    return seed;
  }

  PM->AHBMASK.reg |= PM_AHBMASK_DSU;
  PM->APBBMASK.reg |= PM_APBBMASK_DSU;

  DSU->STATUSA.reg = DSU_STATUSA_DONE | DSU_STATUSA_BERR;
  DSU->ADDR.reg = (uint32_t)data;
  DSU->LENGTH.reg = (uint32_t)len;
  DSU->DATA.reg = seed;
  DSU->CTRL.reg = DSU_CTRL_CRC;

  while ((DSU->STATUSA.reg & DSU_STATUSA_DONE) == 0u)
  {
    /* Wait for completion */
  }

  return DSU->DATA.reg;
}

static uint32_t crc32_region_hw_sw(uint32_t start_addr, uint32_t len)
{
  uint32_t crc = 0xFFFFFFFFu;
  uint32_t aligned_len = len & ~0x3u;

  if (aligned_len > 0u)
  {
    crc = dsu_crc32_aligned(crc, (const void *)start_addr, aligned_len);
  }

  uint32_t remaining = len - aligned_len;
  if (remaining > 0u)
  {
    crc = crc32_update(crc, (const uint8_t *)(start_addr + aligned_len), remaining);
  }

  return crc ^ 0xFFFFFFFFu;
}

static bool application_vector_table_valid(void)
{
  uint32_t *vectors = (uint32_t *)&__sketch_vectors_ptr;
  uint32_t initial_sp = vectors[0];
  uint32_t reset_handler = vectors[1];

  if ((initial_sp < SRAM_START) || (initial_sp > SRAM_END))
  {
    return false;
  }

  if ((reset_handler < APPLICATION_START_ADDRESS) || (reset_handler >= FW_FOOTER_ADDRESS))
  {
    return false;
  }

  if ((reset_handler & 0x1u) == 0u)
  {
    return false;
  }

  return true;
}

static bool app_footer_valid_and_authenticated(void)
{
  fw_footer_t footer;
  memcpy(&footer, (const void *)FW_FOOTER_ADDRESS, FW_FOOTER_SIZE);

  if (footer.magic != FW_FOOTER_MAGIC)
  {
    return false;
  }

  if ((footer.app_length == 0u) || (footer.app_length > (FW_FOOTER_ADDRESS - APPLICATION_START_ADDRESS)))
  {
    return false;
  }

  if ((APPLICATION_START_ADDRESS + footer.app_length) > FW_FOOTER_ADDRESS)
  {
    return false;
  }

  uint32_t calculated_crc = crc32_region_hw_sw(APPLICATION_START_ADDRESS, footer.app_length);
  if (calculated_crc != footer.crc32)
  {
    return false;
  }

  uint8_t calculated_mac[BLAKE2S_MAC_LEN];
  blake2s_mac(
    calculated_mac,
    (const void *)APPLICATION_START_ADDRESS,
    footer.app_length,
    ZK_SECRET_KEY,
    ZK_SECRET_KEY_LEN);

  if (memcmp(calculated_mac, footer.mac_tag, BLAKE2S_MAC_LEN) != 0)
  {
    return false;
  }

  return true;
}

static void delay_ms(uint32_t ms)
{
  if (ms == 0u)
  {
    return;
  }

  uint32_t ticks_per_ms = SystemCoreClock / 1000u;
  if (ticks_per_ms == 0u)
  {
    ticks_per_ms = 1u;
  }

  if (ticks_per_ms > (SysTick_LOAD_RELOAD_Msk + 1u))
  {
    ticks_per_ms = SysTick_LOAD_RELOAD_Msk + 1u;
  }

  SysTick->CTRL = 0u;
  SysTick->LOAD = ticks_per_ms - 1u;
  SysTick->VAL = 0u;
  SysTick->CTRL = SysTick_CTRL_CLKSOURCE_Msk | SysTick_CTRL_ENABLE_Msk;

  while (ms-- > 0u)
  {
    while ((SysTick->CTRL & SysTick_CTRL_COUNTFLAG_Msk) == 0u)
    {
      __NOP();
    }
  }

  SysTick->CTRL = 0u;
  SysTick->VAL = 0u;
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

  if (!application_vector_table_valid())
  {
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

  if (!app_footer_valid_and_authenticated())
  {
    delay_ms(PENALTY_DELAY_MS);
    return;
  }

#ifdef CONFIGURE_PMIC
  jump_to_app = true;
#else
  jump_to_application();
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
