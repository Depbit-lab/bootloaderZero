@echo off
REM Archivo: make.bat
REM Ejecuta el comando 'make' para compilar.
echo Iniciando la compilación...

make %*

IF %ERRORLEVEL% NEQ 0 (
    echo.
    echo ❌ ERROR DE COMPILACION. Presiona cualquier tecla para salir.
    pause > nul
) ELSE (
    echo.
    echo ✅ COMPILACION EXITOSA.
)

REM La ventana se cerrará automáticamente si fue exitosa.