import zlib
import os
import struct
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import secrets

# ============================================
# CONSTANTES (DEBEN COINCIDIR CON BOOTLOADER)
# ============================================
APP_START_ADDR = 0x2000
CRC32_SIZE = 4 # 4 bytes

# **LONGITUD DE CLAVE: 4 BYTES (uint32_t)**
SECRET_KEY_SIZE = 4

class FirmwareSignerApp:
    def __init__(self, master):
        self.master = master
        master.title("ZeroKeyUSB — Payload+K-CRC32 Signer (4-Byte Key)")

        self.file_path = tk.StringVar()
        self.key_path = tk.StringVar()
        self.current_key_bytes = b'\x00' * SECRET_KEY_SIZE
        self.current_key_int = 0x00000000

        master.style = ttk.Style()
        master.style.theme_use('clam')
        master.style.configure('Accent.TButton', background='#6CD75F', foreground='black', borderwidth=1)
        master.style.map('Accent.TButton', background=[('active', '#5CBF4E')])

        # 1) Gestión de Clave Secreta
        key_frame = ttk.LabelFrame(master, text=f"1. Clave Secreta K-CRC32 ({SECRET_KEY_SIZE} Bytes)")
        key_frame.pack(padx=10, pady=10, fill="x")
        
        ttk.Button(key_frame, text="🔑 Generar y Guardar Nueva Clave", command=self.generate_and_save_key).pack(pady=5, padx=5, fill="x")

        row_load = ttk.Frame(key_frame); row_load.pack(fill="x", padx=5, pady=5)
        ttk.Label(row_load, text="Ruta KEY:").pack(side="left")
        ttk.Entry(row_load, textvariable=self.key_path, width=40, state='readonly').pack(side="left", padx=5, fill="x", expand=True)
        ttk.Button(row_load, text="Cargar Key", command=self.load_key_file).pack(side="left")
        
        self.key_status = ttk.Label(key_frame, text="Estado: Clave no cargada.", foreground='red')
        self.key_status.pack(padx=5, pady=5)

        # 2) Firmware
        file_frame = ttk.LabelFrame(master, text="2. Seleccionar Firmware a Firmar (.bin o .hex)")
        file_frame.pack(padx=10, pady=10, fill="x")
        ttk.Entry(file_frame, textvariable=self.file_path, width=50, state='readonly').pack(side="left", padx=5, pady=5, fill="x", expand=True)
        ttk.Button(file_frame, text="Abrir…", command=self.select_firmware_file).pack(side="left", padx=5, pady=5)

        # 3) Firmar
        sign_frame = ttk.Frame(master); sign_frame.pack(padx=10, pady=5, fill="x")
        ttk.Button(sign_frame, text="3. GENERAR PAQUETE (Payload + K-CRC32)", command=self.sign_action, style='Accent.TButton').pack(pady=10)

    # ---------- Gestión de Clave ----------
    def update_key_status(self, key_bytes):
        """Actualiza el estado y el valor interno de la clave."""
        self.current_key_bytes = key_bytes
        self.current_key_int = struct.unpack("<I", key_bytes)[0]
        
        hex_val = f"0x{self.current_key_int:08X}"
        key_status_text = f"Estado: Clave cargada - Valor C: {hex_val}UL"
        self.key_status.config(text=key_status_text, foreground='green')

    def generate_and_save_key(self):
        """Genera una clave aleatoria de 4 bytes y la guarda."""
        try:
            new_key_bytes = secrets.token_bytes(SECRET_KEY_SIZE)
            new_key_int = struct.unpack("<I", new_key_bytes)[0]

            save_path = filedialog.asksaveasfilename(
                title="Guardar archivo de clave secreta",
                defaultextension=".key",
                initialfile="secret_key_4byte.key",
                filetypes=(("Key files", "*.key"), ("All files", "*.*"))
            )
            
            if save_path:
                with open(save_path, "wb") as f:
                    f.write(new_key_bytes)
                
                self.update_key_status(new_key_bytes)
                self.key_path.set(save_path)
                
                messagebox.showinfo(
                    "Clave Generada y Guardada",
                    f"Clave generada y guardada en:\n{save_path}\n\n"
                    "🚨 AVISO CRÍTICO:\n"
                    f"Debes codificar este valor en tu bootloader C:\n"
                    f"#define APPLICATION_SECRET_KEY {hex(new_key_int)}UL"
                )
        except Exception as e:
            messagebox.showerror("Error de Generación", f"Fallo al generar la clave: {e}")

    def load_key_file(self):
        """Carga la clave de un archivo de 4 bytes."""
        f_path = filedialog.askopenfilename(
            title="Seleccionar archivo de clave secreta",
            filetypes=(("Key files", "*.key"), ("All files", "*.*"))
        )
        if f_path:
            try:
                with open(f_path, "rb") as f:
                    key_data = f.read()
                
                if len(key_data) != SECRET_KEY_SIZE:
                    raise ValueError(f"El archivo debe contener exactamente {SECRET_KEY_SIZE} bytes (uint32_t), pero tiene {len(key_data)} bytes.")
                    
                self.update_key_status(key_data)
                self.key_path.set(f_path)
                
                messagebox.showinfo("Clave Cargada", f"Clave cargada con éxito. Valor hexadecimal: {hex(self.current_key_int)}")
                
            except Exception as e:
                self.key_path.set("")
                self.key_status.config(text="Estado: Error al cargar clave.", foreground='red')
                messagebox.showerror("Error de Carga", f"Fallo al cargar la clave: {e}")

    # ---------- Entrada archivos ----------
    def select_firmware_file(self):
        f = filedialog.askopenfilename(title="Seleccionar firmware",
                                       filetypes=(('Firmware', '*.bin *.hex'), ('Todos', '*.*')))
        if f: self.file_path.set(f)

    # ---------- HEX → BIN alineado a 0x2000 ----------
    def hex_to_bin(self, hex_content):
        lines = hex_content.strip().split('\n')
        recs, upper, max_addr = [], 0, 0
        for ln in lines:
            if not ln.startswith(':'): continue
            try:
                length = int(ln[1:3], 16)
                addr = int(ln[3:7], 16)
                rtype = int(ln[7:9], 16)
                data_hex = ln[9:9 + length * 2]
                if rtype == 0x04:
                    upper = int(data_hex, 16) << 16
                elif rtype == 0x00:
                    abs_addr = upper + addr
                    b = bytes.fromhex(data_hex)
                    recs.append((abs_addr, b))
                    max_addr = max(max_addr, abs_addr + len(b))
            except ValueError:
                continue
        
        if max_addr <= APP_START_ADDR:
             raise ValueError("HEX sin registros de datos válidos en la región de aplicación (a partir de 0x2000).")
            
        fw = bytearray([0xFF] * max_addr)
        for addr, b in recs:
            if addr < len(fw):
               fw[addr:addr + len(b)] = b
               
        return fw[APP_START_ADDR:]  

    # ---------- K-CRC32 y empaquetado ----------
    def sign_action(self):
        path = self.file_path.get()
        if not path:
            messagebox.showerror("Falta archivo", "Selecciona un firmware .bin o .hex.")
            return

        if self.current_key_int == 0x00000000:
             messagebox.showerror("Falta clave", f"Carga o genera una clave secreta de {SECRET_KEY_SIZE} bytes antes de firmar.")
             return

        try:
            ext = os.path.splitext(path)[1].lower()
            if ext == ".hex":
                with open(path, "r") as f:
                    payload = bytearray(self.hex_to_bin(f.read()))
            elif ext == ".bin":
                with open(path, "rb") as f:
                    payload = bytearray(f.read())
            else:
                messagebox.showerror("Formato no soportado", "Usa .bin o .hex")
                return

            if not payload:
                 raise ValueError("El firmware cargado está vacío o no contiene datos de aplicación.")
                
            MAX_PAYLOAD_SIZE = 0x3DFFC 
            if len(payload) > MAX_PAYLOAD_SIZE:
                raise ValueError(f"El firmware es demasiado grande ({len(payload)} bytes). Máximo permitido: {MAX_PAYLOAD_SIZE} bytes.")
                
            # --- Lógica de K-CRC32 (Réplica exacta de la lógica C) ---
            
            # 1. Inicialización (0xFFFFFFFF)
            crc = 0xFFFFFFFF
            
            # 2. Actualizar con el Payload
            crc = zlib.crc32(bytes(payload), crc) & 0xFFFFFFFF
            
            # 3. Actualizar con la clave secreta (4 bytes)
            crc = zlib.crc32(self.current_key_bytes, crc) & 0xFFFFFFFF
            
            # 4. Finalización (XOR 0xFFFFFFFF)
            final_k_crc32 = (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF 

            # Estructura del K-CRC32 (Little Endian)
            crc32_bytes = struct.pack("<I", final_k_crc32)
            
            # Paquete final: Payload + K-CRC32 (4 bytes)
            final_package = bytes(payload) + crc32_bytes

            # --- Guardar archivo final ---
            out_dir = os.path.dirname(path)
            base = os.path.basename(path).rsplit('.', 1)[0]
            zkfw_out = os.path.join(out_dir, f"{base}_keyed_crc.bin")  
            
            with open(zkfw_out, "wb") as f: f.write(final_package)

            messagebox.showinfo(
                "✅ Éxito",
                "Firma K-CRC32 realizada.\n\n"
                f"Clave usada: 0x{self.current_key_int:08X}UL (4 Bytes)\n"
                f"K-CRC32 Calculado: 0x{final_k_crc32:08X}\n"
                f"Archivo completo para flashear: {zkfw_out}"
            )

        except Exception as e:
            messagebox.showerror("Error al generar el paquete", f"Fallo: {e}")


# --- MAIN ---
if __name__ == "__main__":
    try:
        import zlib, struct
        root = tk.Tk()
        app = FirmwareSignerApp(root)
        root.mainloop()
    except ImportError as e:
        messagebox.showerror("Error de Dependencia", f"Módulo faltante: {e}. Asegúrate de que tu instalación de Python incluye 'zlib' y 'struct'.")