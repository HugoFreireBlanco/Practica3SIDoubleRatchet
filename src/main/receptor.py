import socket 
import threading
from commons import COMUNICATION_PORT, DEFAULT_IP


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
    print("----Receiver iniciado----")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((DEFAULT_IP, COMUNICATION_PORT))
    server.listen(1)

    print("Esperando conexión...")
    conn, addr = server.accept()
    print("Cliente conectado:", addr)

    threading.Thread(target=receive_data, args=(conn,), daemon=True).start()
    threading.Thread(target=send_data, args=(conn,), daemon=True).start()

    # Mantener el programa vivo
    while True:
        pass

if __name__ == "__main__":
    main()