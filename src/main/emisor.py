import socket
import threading

from commons import BUFFER_SIZE, COMUNICATION_PORT, DEFAULT_IP, KDF_CK, KDF_RK, ROOT_KEY, decrypt, deserialize_public_key, encrypt, generate_df_key_pair, obtain_shared_secret, receive_public_key, send_public_key, serialize_public_key

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
    #flujo que tiene que seguir esto 
    # se recibe un texto que lleva la clave delante 
    # se extrae la clave y se compara con la que tenemos en el otro extremo 
    # si la clave que se recibe es la misma que la que tenemmos guardada usamos directamente el ratched simetrico para tener la clave de descifrado
    # si la clave que se recibe es diferente tenemos que hacer un ratchet de diffie para tener la nueva clave de recepción y con eso hacemos el ratchet simetrico para la clave de descicfrado
    #(esto es para la clave de recepción : tenemos un chain key para envio y otro para recepción)

    while True:
        data = socket.recv(BUFFER_SIZE)
        if not data:
            break
        received_public_key_bytes = data[:32]
        print("Received public key bytes:", received_public_key_bytes.hex())
        received_ciphertext = data[32:]
        if other_public_key and serialize_public_key(other_public_key) == received_public_key_bytes:
            print("Las claves públicas son iguales")
            #usas eso con el ratchet simetrico para obtener la message key
            if(receiving_chain_key is None):
                message_key , receiving_chain_key = KDF_CK(chain_key)
            else: message_key , receiving_chain_key = KDF_CK(receiving_chain_key)
        else:
            print("Las claves públicas son diferentes")
            # generar nueva ratchet de diffie hellman
            received_public_key = deserialize_public_key(received_public_key_bytes)
            other_public_key = received_public_key
            secret = obtain_shared_secret(private_key, received_public_key)
            new_root_key , receiving_chain_key = KDF_RK(new_root_key, secret)
            message_key , receiving_chain_key = KDF_CK(receiving_chain_key)

        print("Received chain key:", receiving_chain_key.hex())
        plaintext = decrypt(message_key, received_ciphertext, None)
        print("\nRecibido:", plaintext.decode() , end="\n")

def main():
    global private_key
    global public_key
    global new_root_key
    global sending_chain_key
    global chain_key
    global other_public_key

    print("----Client iniciado----")
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((DEFAULT_IP, COMUNICATION_PORT))
    except ConnectionRefusedError:
        print("Error: no se pudo conectar con el servidor")
        exit(1)

    print("Conectado al servidor")

    print("Comenzando el proceso de intercambio de claves")
    
    private_key , public_key = generate_df_key_pair()
    print("Enviando clave publica al otro extremo")
    send_public_key(client, public_key)



    print("Recibiendo la clave del otro extremo")
    received_public_key = receive_public_key(client)

    #con esto ya calculamos las primeras claves para el ratchet (tanto envio como recepcion)
    secret = obtain_shared_secret(private_key, received_public_key)
    print("secret bytes:", secret.hex())

    new_root_key = ROOT_KEY

    threading.Thread(target=receive_data, args=(client, ), daemon=True).start()

    #en el bucle de envío simplemente hacemos el ratchet simetrico para obtener la clave necesria y una vez enviado en messaje hacemos un ratched de diffie nuevo (generando nuevo par de claves)
    # la nueva clave es la que usamos para el siguiente envio
    while True:
        
        data = input("Enviar(exit para salir): ")
        if data.lower() == "exit":
            break

        # Generar nueva clave DH ANTES de enviar (excepto en el primer mensaje)
        if other_public_key is not None:
            private_key, public_key = generate_df_key_pair()
            secret = obtain_shared_secret(private_key, other_public_key)

        print("previous root key:", new_root_key.hex())

        new_root_key , sending_chain_key = KDF_RK(new_root_key, secret)
        message_key , sending_chain_key = KDF_CK(sending_chain_key)

        print("root key:", new_root_key.hex())
        print("message key:", message_key.hex())
            
        ciphertext = encrypt(message_key, data.encode(), None)
        # Envía: clave pública + mensaje cifrado
        public_key_bytes = serialize_public_key(public_key)
        client.send(public_key_bytes + ciphertext)
        print("Enviado:", data)
        

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