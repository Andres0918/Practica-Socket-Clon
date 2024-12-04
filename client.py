import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from tkinter import simpledialog, messagebox
from cryptography.fernet import Fernet

# Clave simétrica compartida (debe ser la misma que en el servidor)
KEY = b'L9tB8XrT_7hkTovA9uQzkBpE8T6gn15c8M6bUciTPfQ='
cipher = Fernet(KEY)

class ChatClient:
    def __init__(self, host, port):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((host, port))

        # Interfaz gráfica
        self.root = tk.Tk()
        self.root.title("Chat Seguro")
        self.root.geometry("400x600")
        self.root.configure(bg="#48C756")  # Fondo principal con color púrpura

        # Estilo del área de chat
        self.chat_area = scrolledtext.ScrolledText(
            self.root, state=tk.DISABLED, width=50, height=20,
            bg="#FFFFFF", fg="#000000", font=("Arial", 12), relief=tk.FLAT
        )
        self.chat_area.grid(row=0, column=0, padx=10, pady=10, columnspan=2, sticky="nsew")

        # Campo de entrada de mensaje
        self.message_entry = tk.Entry(
            self.root, width=40, font=("Arial", 12),
            bg="#F0F0F0", fg="#000000", relief=tk.FLAT, insertbackground="#4A4DE6"
        )
        self.message_entry.grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)
        self.message_entry.bind("<Return>", self.send_message)

        # Botón enviar
        self.send_button = tk.Button(
            self.root, text="🚀", command=self.send_message,
            bg="#4A4DE6", fg="#FFFFFF", font=("Arial", 12, "bold"), relief=tk.FLAT
        )
        self.send_button.grid(row=1, column=1, padx=10, pady=10)

        # Configuración del grid para expandir
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # Solicitar el nombre de usuario
        self.username = simpledialog.askstring(
            "Nombre de Usuario", "Ingresa tu nombre de usuario:", parent=self.root
        )
        if not self.username:
            messagebox.showerror("Error", "Debe ingresar un nombre de usuario.")
            self.root.destroy()

            return

        # Enviar el nombre de usuario cifrado al servidor
        self.client.send(cipher.encrypt(self.username.encode('utf-8')))

        # Hilo para recibir mensajes
        self.running = True
        threading.Thread(target=self.receive_messages, daemon=True).start()

        # Manejo de cierre de ventana
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def receive_messages(self):
        """Recibe mensajes del servidor y los muestra en la interfaz gráfica."""
        buffer = ""  # Almacenar datos parciales
        while self.running:
            try:
                data = self.client.recv(1024)
                if not data:
                    raise ConnectionResetError("Conexión cerrada por el servidor.")

                # Agregar datos al buffer y descifrar
                buffer += cipher.decrypt(data).decode('utf-8')

                # Procesar mensajes completos en el buffer
                while "\n" in buffer:
                    message, buffer = buffer.split("\n", 1)
                    self.display_message(message)

            except ConnectionResetError:
                print("Conexión con el servidor cerrada.")
                self.running = False
                self.client.close()
                break
            except Exception as e:
                print(f"Error al recibir mensaje: {e}")
                self.running = False
                self.client.close()
                break

    def send_message(self, event=None):
        """Envía un mensaje al servidor."""
        message = self.message_entry.get()
        if message:
            try:
                # Enviar el mensaje directamente al servidor
                encrypted_message = cipher.encrypt(message.encode('utf-8'))
                self.client.send(encrypted_message)
                self.message_entry.delete(0, tk.END)
            except Exception as e:
                print(f"Error al enviar mensaje: {e}")
                self.display_message("No se pudo enviar el mensaje. Revisa la conexión.")

    def display_message(self, message):
        """Muestra un mensaje en la interfaz gráfica."""
        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.insert(tk.END, message + "\n")
        self.chat_area.config(state=tk.DISABLED)
        self.chat_area.yview(tk.END)

    def on_closing(self):
        """Maneja el cierre de la ventana."""
        self.running = False
        try:
            self.client.close()
        except Exception as e:
            print(f"Error al cerrar la conexión: {e}")
        self.root.destroy()

    def run(self):
        """Inicia la interfaz gráfica."""
        self.root.mainloop()


if __name__ == "__main__":
    host = '127.0.0.1'
    port = 55555

    client = ChatClient(host, port)
    client.run()