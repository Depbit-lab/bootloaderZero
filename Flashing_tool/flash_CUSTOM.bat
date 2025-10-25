@echo off
echo === SAMD21 FLASH TOOL ===
echo.

:: Ejecutar J-Link usando ruta absoluta
echo Flashing bootloader + firmware to SAMD21...
echo ------------------------------------------
"C:\Program Files\SEGGER\JLink\JLink.exe" -CommanderScript flash_CUSTOM.jlink
echo ------------------------------------------

echo.
pause
