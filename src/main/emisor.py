import socket
import threading

from commons import BUFFER_SIZE, COMUNICATION_PORT, DEFAULT_IP, KDF_CK, KDF_RK, ROOT_KEY, decrypt, deserialize_public_key, encrypt, generate_df_key_pair, obtain_shared_secret, receive_public_key, send_public_key, serialize_public_key, safe_print

#primero tengo que hacer el intercambio inicial de claves

new_root_key = None
other_public_key = None
sending_chain_key = None
receiving_chain_key = None
chain_key = None
private_key = None
public_key = None

def receive_data(socket):
    global new_root_key
    global other_public_key
    global receiving_chain_key

    while True:
        data = socket.recv(BUFFER_SIZE)
        if not data:
            break
        received_public_key_bytes = data[:32]
        safe_print("\n[RECEPTOR] Clave pública recibida:", received_public_key_bytes.hex()[:16] + "...")
        received_ciphertext = data[32:]
        if other_public_key and serialize_public_key(other_public_key) == received_public_key_bytes:
            safe_print("[RECEPTOR] → Usando ratchet simétrico (clave igual)")
            if(receiving_chain_key is None):
                message_key , receiving_chain_key = KDF_CK(chain_key)
            else: message_key , receiving_chain_key = KDF_CK(receiving_chain_key)
        else:
            safe_print("[RECEPTOR] → Ejecutando DH ratchet (clave diferente)")
            received_public_key = deserialize_public_key(received_public_key_bytes)
            other_public_key = received_public_key
            secret = obtain_shared_secret(private_key, received_public_key)
            new_root_key , receiving_chain_key = KDF_RK(new_root_key, secret)
            chain_key = receiving_chain_key
            message_key , receiving_chain_key = KDF_CK(receiving_chain_key)

        plaintext = decrypt(message_key, received_ciphertext, None)
        safe_print("[RECEPTOR] 📨 Recibido: " + plaintext.decode())
        safe_print("Enviar(exit para salir): ", end="", flush=True)

def main():
    global private_key
    global public_key
    global new_root_key
    global sending_chain_key
    global chain_key
    global other_public_key

    safe_print("━" * 70)
    safe_print("        🔐 CLIENTE - DOUBLE RATCHET ENCRYPTION PROTOCOL")
    safe_print("━" * 70)
    
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((DEFAULT_IP, COMUNICATION_PORT))
    except ConnectionRefusedError:
        safe_print("❌ Error: no se pudo conectar con el servidor")
        exit(1)

    safe_print("✓ Conectado al servidor\n")
    safe_print("🔄 Intercambiando claves públicas iniciales...")
    
    private_key , public_key = generate_df_key_pair()
    send_public_key(client, public_key)
    safe_print("  ✓ Clave pública enviada")

    received_public_key = receive_public_key(client)
    safe_print("  ✓ Clave pública recibida\n")

    secret = obtain_shared_secret(private_key, received_public_key)
    new_root_key = ROOT_KEY

    threading.Thread(target=receive_data, args=(client, ), daemon=True).start()
    
    safe_print("✓ Listo para comunicarse")
    safe_print("━" * 70 + "\n")

    while True:
        data = input("Enviar(exit para salir): ")
        if data.lower() == "exit":
            break

        if other_public_key is not None:
            private_key, public_key = generate_df_key_pair()
            secret = obtain_shared_secret(private_key, other_public_key)

        new_root_key , sending_chain_key = KDF_RK(new_root_key, secret)
        message_key , sending_chain_key = KDF_CK(sending_chain_key)
            
        ciphertext = encrypt(message_key, data.encode(), None)
        public_key_bytes = serialize_public_key(public_key)
        client.send(public_key_bytes + ciphertext)
        safe_print("[EMISOR] 📤 Enviado: " + data)
        

if __name__ == "__main__":
    main()



# voy a usar un solo ratchet simetrico que voy a usar para tener tanto al clave de envio como de recepción
# tras hacer un intercambio inicial comienza el envio del mensaje y voy a ejecutar el ratchet simetrico para generar una nueva
# clave de envio despues de enviar el mensaje para tener una clave nueva a la hora de enviar el siguiente
# el receptor recibe el mensaje con la clave publica delante que es la que usa para generar 

# el ratchet simetrico se usa cada vez que queremos generar la clave de envio y usamos eso para mantener 

# como las root keys están siempre sincronizadas (porque al enviar de un extremo obteniendo la root key el otro 
# mira que la public key que el llega es diferente y ya obtiene la nueva root key que es la misma)

# en el primer intercambio esto que tengo va a funcionar porque la clave publica que se envia es la que tiene el receptor y no se tiene que calcular 
# una interacion nueva del ratchet de diffie hellman