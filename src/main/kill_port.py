#!/usr/bin/env python3
import subprocess
import sys
from commons import COMUNICATION_PORT

def kill_process_on_port(port):
    """
    Mata el proceso que está escuchando en el puerto especificado.
    """
    try:
        # En Linux/Mac: usa lsof para encontrar el proceso
        result = subprocess.run(
            ["lsof", "-i", f":{port}", "-t"],
            capture_output=True,
            text=True
        )
        
        if result.stdout.strip():
            pids = result.stdout.strip().split('\n')
            for pid in pids:
                if pid:
                    subprocess.run(["kill", "-9", pid])
                    print(f"Proceso {pid} matado en puerto {port}")
        else:
            print(f"No hay proceso escuchando en el puerto {port}")
            
    except FileNotFoundError:
        # Si lsof no está disponible, usa netstat (alternativa)
        print("Intentando con netstat...")
        try:
            result = subprocess.run(
                ["netstat", "-tlnp"],
                capture_output=True,
                text=True
            )
            for line in result.stdout.split('\n'):
                if f":{port}" in line:
                    parts = line.split()
                    if len(parts) > 6:
                        pid = parts[6].split('/')[0]
                        subprocess.run(["kill", "-9", pid])
                        print(f"Proceso {pid} matado en puerto {port}")
        except Exception as e:
            print(f"Error: {e}")
    except Exception as e:
        print(f"Error al intentar matar el proceso: {e}")

if __name__ == "__main__":
    print(f"Intentando liberar puerto {COMUNICATION_PORT}...")
    kill_process_on_port(COMUNICATION_PORT)
