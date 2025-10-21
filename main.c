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
#include <stdbool.h>
#include <sam.h>
#include "sam_ba_monitor.h"
#include "board_definitions.h"
#include "board_driver_i2c.h"
#include "board_driver_pmic.h"
#include "board_driver_jtag.h"
#include "sam_ba_usb.h"
#include "sam_ba_cdc.h"

// --- Configuración de flag en el final de la Flash de aplicación ---
#define FLASH_PAGE_SIZE        (64u)          // SAMD21: 64 bytes
#define MAX_FLASH_ADDR         (0x00040000u)  // Ajusta si tu parte tiene otra Flash size
#define FLAG_ADDRESS           (MAX_FLASH_ADDR - 4u)

#define APP_VERIFIED_MAGIC     (0xCAFEF00Du)
#define APP_PENALIZED_MAGIC    (0xDEADBEEFu)

static inline void nvm_wait_ready(void) {
  while (!(NVMCTRL->INTFLAG.reg & NVMCTRL_INTFLAG_READY)) { /* wait */ }
}

// Precaución: escribe una PÁGINA (64B) con el contenido de 'src' (64B)
static void nvm_write_page(uint32_t dst_addr, const uint8_t *src64B) {
  // Forzar escritura manual (WP explícito)
  NVMCTRL->CTRLB.bit.MANW = 1;

  // 1) Volcar 64B al "page buffer" escribiendo en la dirección mapeada
  //    (16 palabras de 32 bits)
  volatile uint32_t *dst32 = (volatile uint32_t *)(dst_addr & ~(FLASH_PAGE_SIZE - 1u));
  const uint32_t *src32 = (const uint32_t *)src64B;

  for (uint32_t i = 0; i < (FLASH_PAGE_SIZE / 4u); i++) {
    dst32[i] = src32[i];
  }

  // 2) Lanzar "Write Page" sobre esa página
  NVMCTRL->ADDR.reg = ((uint32_t)dst32) / 2u;  // Dirección en palabras
  nvm_wait_ready();
  NVMCTRL->CTRLA.reg = NVMCTRL_CTRLA_CMDEX_KEY | NVMCTRL_CTRLA_CMD_WP;
  nvm_wait_ready();
}

// Escribe el magic en la última palabra (FLAG_ADDRESS) SIN borrar fila
static void flash_write_flag(uint32_t magic) {
  uint32_t page_base = FLAG_ADDRESS & ~(FLASH_PAGE_SIZE - 1u);
  uint8_t  buf[FLASH_PAGE_SIZE];

  // 1) Copiar contenido actual de la página (64B)
  const uint8_t *p = (const uint8_t *)page_base;
  for (uint32_t i = 0; i < FLASH_PAGE_SIZE; i++) buf[i] = p[i];

  // 2) Inyectar magic en el offset exacto dentro de la página
  uint32_t off = (uint32_t)(FLAG_ADDRESS - page_base);
  buf[off + 0] = (uint8_t)(magic >> 0);
  buf[off + 1] = (uint8_t)(magic >> 8);
  buf[off + 2] = (uint8_t)(magic >> 16);
  buf[off + 3] = (uint8_t)(magic >> 24);

  // 3) Programar toda la página (sin row erase)
  nvm_write_page(page_base, buf);
}

// Busy-wait basado en tu estilo de 500ms (125000 iteraciones @ 1MHz)
static void delay_ms(uint32_t ms) {
  // Con 125000 iteraciones ≈ 500 ms => 250000 iter/s => 250 iter/ms
  const uint32_t iters_per_ms = 250u;
  uint32_t total = iters_per_ms * ms;
  for (uint32_t i = 0; i < total; i++) {
    __asm__ __volatile__("");
  }
}

// Stub de verificación criptográfica lenta (reemplaza por la real)
static bool verify_application_crypto_check(void) {
  // TODO: implementar la verificación de firma real (puede tardar minutos)
  // Devuelve true si la app es auténtica y válida; false en caso contrario.
  return false;
}

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

  uint32_t flag = *(volatile const uint32_t *)FLAG_ADDRESS;

  bool should_jump_fast = false;

  if (flag == APP_VERIFIED_MAGIC || flag == APP_PENALIZED_MAGIC) {
    should_jump_fast = true;
  } else {
    bool ok = verify_application_crypto_check();
    if (ok) {
      flash_write_flag(APP_VERIFIED_MAGIC);
      should_jump_fast = true;
    } else {
      delay_ms(15000u);
      flash_write_flag(APP_PENALIZED_MAGIC);
      should_jump_fast = true;
    }
  }

#ifdef CONFIGURE_PMIC
  if (should_jump_fast) {
    jump_to_app = true;
  }
#else
  if (should_jump_fast) {
    jump_to_application();
  }
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
