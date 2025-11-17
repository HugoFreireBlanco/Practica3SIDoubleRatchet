import socket
import threading
from commons import COMUNICATION_PORT, DEFAULT_IP

#primero tengo que hacer el intercambio inicial de claves

def receive_data(socket):
    while True:
        data = socket.recv(1024)
        if not data:
            break
        print("Recibido:", data.decode())

def send_data(socket):
    while True:
        data = input("Enviar: ")
        socket.send(data.encode())
        print("Enviado:", data)

def main():
    print("----Client iniciado----")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((DEFAULT_IP, COMUNICATION_PORT))
    threading.Thread(target=receive_data, args=(s,), daemon=True).start()
    threading.Thread(target=send_data, args=(s,), daemon=True).start()

    # Mantener el programa vivo
    while True:
        pass

if __name__ == "__main__":
    main()