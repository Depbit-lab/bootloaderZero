import hashlib
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, scrolledtext
import struct # Para empaquetar los valores del footer (Little Endian)
# Importar una implementación de BLAKE2s para Python.
# Usaremos 'pyblake2' si está disponible, si no, usaremos 'hashlib' con fallback.
try:
    import pyblake2
    BLAKE2S_FUNC = pyblake2.blake2s
except ImportError:
    # Si pyblake2 no está instalado, usamos hashlib.blake2s
    # La clave de 32 bytes y el digest de 16 bytes deben ser manejados
    def BLAKE2S_FUNC(data, key, digest_size=16):
        return hashlib.blake2s(data, key=key, digest_size=digest_size)
    print("Advertencia: Usando hashlib.blake2s. Si es posible, instale 'pyblake2' para un rendimiento óptimo.")

# --- CONSTANTES DEL BOOTLOADER (NUEVA ARQUITECTURA: FOOTER) ---
# **ESTAS CONSTANTES DEBEN COINCIDIR EXACTAMENTE CON 'zk_fw_footer.h' y 'zk_secret.h'**
# Dirección de inicio de la aplicación, ignorada en la firma, relevante para el flasheo.
APPLICATION_START_ADDRESS = 0x2000
FW_FOOTER_MAGIC = 0x21DA07AD
MAC_SIZE = 16            # 16 bytes para BLAKE2s (BLAKE2s-128)
KEY_SIZE = 32            # 32 bytes para la clave secreta BLAKE2s
CRC32_SIZE = 4
LENGTH_SIZE = 4
FOOTER_SIZE = 28         # MAC_SIZE (16) + CRC32 (4) + Length (4) + Magic (4)

# La clave secreta debe ser idéntica a la de zk_secret.h.
# ¡ADVERTENCIA: Esta clave es de PRUEBA y no debe usarse en producción!
ZK_SECRET_KEY = bytes([
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
])

class FirmwareSignerApp:
    def __init__(self, master):
        self.master = master
        master.title("ZeroKeyUSB Firmware Signer (BLAKE2s Footer)")

        self.file_path = tk.StringVar()
        self.key_path = tk.StringVar()
        self.master_key_bytes = ZK_SECRET_KEY # Usaremos la clave incrustada ZK_SECRET_KEY

        # Configuración de estilo (mantenemos el estilo)
        master.style = ttk.Style()
        master.style.theme_use('clam')
        master.style.configure('Accent.TButton', background='#6CD75F', foreground='black', borderwidth=1)
        master.style.map('Accent.TButton', background=[('active', '#5CBF4E')])

        # === 1. Generación y Carga de Claves (Simplificado/Explicación) ===
        gen_frame = ttk.LabelFrame(master, text="1. Clave Maestra (BLAKE2s) - INCORPORADA")
        gen_frame.pack(padx=10, pady=10, fill="x")
        ttk.Label(gen_frame, text="🚨 ADVERTENCIA: La clave de firma (32 bytes) ya está incrustada en esta herramienta y en el Bootloader.").pack(pady=5, padx=5)
        ttk.Label(gen_frame, text="Esto es para el flujo de firma offline. La clave es:").pack(padx=5)
        self.key_display = scrolledtext.ScrolledText(gen_frame, height=3, width=50, state='normal')
        self.key_display.insert(tk.END, ZK_SECRET_KEY.hex().upper())
        self.key_display.config(state='disabled')
        self.key_display.pack(padx=5, pady=5, fill="x", expand=True)

        # === 2. Selección de Firmware y Firma ===
        file_frame = ttk.LabelFrame(master, text="2. Seleccionar Firmware a Firmar")
        file_frame.pack(padx=10, pady=10, fill="x")

        ttk.Entry(file_frame, textvariable=self.file_path, width=50, state='readonly').pack(side="left", padx=5, pady=5, fill="x", expand=True)
        ttk.Button(file_frame, text="Abrir Firmware...", command=self.select_firmware_file).pack(side="left", padx=5, pady=5)

        sign_frame = ttk.Frame(master)
        sign_frame.pack(padx=10, pady=5, fill="x")

        ttk.Button(sign_frame, text="3. FIRMAR & AÑADIR FOOTER", command=self.sign_action, style='Accent.TButton').pack(pady=10)

        # Info del Footer
        footer_info_frame = ttk.LabelFrame(master, text="Footer de Seguridad")
        footer_info_frame.pack(padx=10, pady=10, fill="x")
        ttk.Label(footer_info_frame, text=f"MAC Algorithm: BLAKE2s-128 ({MAC_SIZE} bytes)").pack(padx=5, pady=2, anchor='w')
        ttk.Label(footer_info_frame, text=f"Total Footer Size: {FOOTER_SIZE} bytes").pack(padx=5, pady=2, anchor='w')
        ttk.Label(footer_info_frame, text="La salida es un BINARIO **con el footer añadido** al final.").pack(padx=5, pady=2, anchor='w')
        
    # --- HELPERS ---
    def _calculate_crc32(self, data):
        """Calcula el CRC32 (Poly=0xEDB88320) del payload."""
        # Implementación de CRC32 estándar (IEEE 802.3)
        # Esto es crucial, debe coincidir con la implementación del bootloader.
        crc = 0xFFFFFFFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xEDB88320
                else:
                    crc >>= 1
        return crc ^ 0xFFFFFFFF
    
    def _calculate_mac_blake2s(self, data, key):
        """Calcula la MAC BLAKE2s-128 (16 bytes) del payload."""
        # La clave ya está definida en ZK_SECRET_KEY.
        # Usa la función BLAKE2S_FUNC definida globalmente.
        h = BLAKE2S_FUNC(data, key=key, digest_size=MAC_SIZE)
        return h.digest()
    
    # --- MÉTODOS DE LA APLICACIÓN ---
    def select_firmware_file(self):
        """Abre el diálogo para seleccionar el archivo binario o hex."""
        filetypes = (
            ('Firmware files', '*.bin *.hex'),
            ('All files', '*.*')
        )
        filepath = filedialog.askopenfilename(
            title='Seleccionar archivo de firmware',
            filetypes=filetypes
        )
        if filepath:
            self.file_path.set(filepath)

    def hex_to_bin(self, hex_content):
        """Convierte contenido Intel HEX a binario RAW, rellenando con 0xFF y ajustando el offset."""
        # Se asume que la aplicación comienza en 0x2000 (APPLICATION_START_ADDRESS)
        lines = hex_content.strip().split('\n')
        recs = []
        upper = 0
        max_addr = 0
        APP_START_ADDR = APPLICATION_START_ADDRESS

        for ln in lines:
            if not ln.startswith(':'): continue
            try:
                length = int(ln[1:3], 16)
                addr = int(ln[3:7], 16)
                type = int(ln[7:9], 16)
                data_hex = ln[9:9 + length * 2]
                
                if type == 0x04: upper = int(data_hex, 16) << 16; continue
                if type == 0x00:
                    abs_addr = upper + addr
                    bytes_data = bytes.fromhex(data_hex)
                    recs.append({'addr': abs_addr, 'bytes': bytes_data})
                    max_addr = max(max_addr, abs_addr + len(bytes_data))
            except ValueError:
                continue
        
        if max_addr == 0:
            raise ValueError("No se encontraron registros de datos válidos en el archivo HEX.")
        
        # El buffer se dimensiona desde 0 hasta max_addr, pero solo se devuelve lo que empieza en 0x2000
        firmware_buffer = bytearray([0xFF] * max_addr)
        for r in recs:
            firmware_buffer[r['addr']:r['addr'] + len(r['bytes'])] = r['bytes']

        # Devolver solo la porción de la aplicación (0x2000 en adelante)
        if max_addr < APP_START_ADDR:
             raise ValueError(f"El firmware es demasiado pequeño, no llega a la dirección de inicio {hex(APP_START_ADDR)}.")
             
        # Eliminar 0xFF finales que no sean parte del firmware útil
        firmware_data = firmware_buffer[APP_START_ADDR:]
        while firmware_data and firmware_data[-1] == 0xFF:
            firmware_data.pop()
            
        return firmware_data

    def sign_action(self):
        """Calcula el CRC32 y la MAC BLAKE2s y añade el footer al archivo binario."""
        input_filepath = self.file_path.get()
        
        try:
            file_extension = os.path.splitext(input_filepath)[1].lower()
            if file_extension == '.hex':
                with open(input_filepath, "r") as f:
                    # firmware_data_raw es un bytearray que comienza en 0x2000
                    firmware_data_raw = self.hex_to_bin(f.read())
            elif file_extension == '.bin':
                with open(input_filepath, "rb") as f:
                    firmware_data_raw = bytearray(f.read())
            else:
                messagebox.showerror("Error de Archivo", "Formato de archivo no compatible. Use .bin o .hex.")
                return

            # 1. Calcular el CRC32
            # Se usa el bytearray de la aplicación como payload
            app_length = len(firmware_data_raw)
            if app_length == 0:
                 raise ValueError("El archivo de firmware está vacío después del procesamiento.")
                 
            calculated_crc32 = self._calculate_crc32(firmware_data_raw)
            
            # 2. Calcular la MAC BLAKE2s
            calculated_mac = self._calculate_mac_blake2s(firmware_data_raw, self.master_key_bytes)
            
            # 3. Empaquetar el Footer (Little Endian, como ARM)
            # struct.pack('<I', value) -> Little Endian Unsigned Int (4 bytes)
            footer_data = b''
            footer_data += struct.pack('<I', FW_FOOTER_MAGIC)
            footer_data += struct.pack('<I', app_length)
            footer_data += struct.pack('<I', calculated_crc32)
            footer_data += calculated_mac # Es un bytearray/bytes de 16 bytes
            
            # Verificar el tamaño final
            if len(footer_data) != FOOTER_SIZE:
                raise Exception(f"Error de empaquetado del footer. Tamaño esperado: {FOOTER_SIZE}, obtenido: {len(footer_data)}")

            # 4. Crear el archivo de salida (firmware + footer)
            output_data = firmware_data_raw + footer_data

            # 5. Escribir el archivo de salida
            output_dir = os.path.dirname(input_filepath)
            filename_base = os.path.basename(input_filepath).split('.')[0]
            output_filepath = os.path.join(output_dir, f"{filename_base}_signed_footer.bin")

            with open(output_filepath, "wb") as f:
                f.write(output_data)

            messagebox.showinfo("✅ Éxito", 
                                f"Firmware firmado exitosamente con BLAKE2s.\n"
                                f"CRC32: 0x{calculated_crc32:08X}\n"
                                f"MAC (16B): {calculated_mac.hex().upper()}\n"
                                f"Tamaño del Archivo de Salida (Firmware + Footer): {len(output_data)} bytes\n"
                                f"Guardado como:\n{output_filepath}")

        except Exception as e:
            messagebox.showerror("Error de Firma", f"Fallo al firmar: {e}")


# --- EJECUCIÓN DE LA APLICACIÓN ---
if __name__ == "__main__":
    root = tk.Tk()
    app = FirmwareSignerApp(root)
    root.mainloop()