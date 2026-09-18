# client.py
import socket
import struct
import threading
import sys
import os
import pickle
import hashlib # <--- Pour le mot de passe

from crypto.kem import client_encapsulate
from crypto.signature import ClientSigner
from crypto.symmetric import derive_aes_key, encrypt_aes_gcm, decrypt_aes_gcm

HOST = "127.0.0.1"
PORT = 5000

def get_signer(username):
    filename = f"{username}.key"
    if os.path.exists(filename):
        try:
            with open(filename, "rb") as f:
                return pickle.load(f)
        except: pass
    
    signer = ClientSigner()
    with open(filename, "wb") as f:
        pickle.dump(signer, f)
    return signer

def send_data(sock, data):
    length_prefix = struct.pack('!I', len(data))
    sock.sendall(length_prefix + data)

def recv_data(sock):
    try:
        raw_len = recv_exact(sock, 4)
        if not raw_len: return None
        msg_len = struct.unpack('!I', raw_len)[0]
        return recv_exact(sock, msg_len)
    except: return None

def recv_exact(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet: return None
        data += packet
    return data

# Modifie SEULEMENT cette fonction dans client.py

def receive_loop(sock, aes_key):
    while True:
        try:
            packet = recv_data(sock)
            if not packet:
                print("\n[INFO] Déconnecté du serveur.")
                os._exit(0)

            nonce = packet[:12]
            ct = packet[12:-16]
            tag = packet[-16:]
            
            # Déchiffrement
            plaintext_bytes = decrypt_aes_gcm(aes_key, nonce, ct, tag)
            plaintext = plaintext_bytes.decode('utf-8')
            
            # 1. On vérifie si "ACK_SYS:" est PRÉSENT dans le message (peu importe le pseudo devant)
            if "ACK_SYS:" in plaintext:
                # C'est un accusé de réception, on affiche le check
                print(f" [✓ Reçu]") 
                # On utilise 'continue' pour passer à la prochaine boucle
                # Cela empêche de répondre à un ACK par un autre ACK
                continue 

            # 2. Si on arrive ici, c'est un vrai message
            print(f"\r{plaintext}\n> ", end="") 
            sys.stdout.flush()

            # 3. On envoie un ACK seulement si ce n'est pas un message système du serveur
            if not plaintext.startswith("Serveur :"):
                ack_msg = "ACK_SYS: Confirmation"
                nonce_ack, ct_ack, tag_ack = encrypt_aes_gcm(aes_key, ack_msg.encode('utf-8'))
                send_data(sock, nonce_ack + ct_ack + tag_ack)

        except Exception as e:
            break

def run_client():
    # --- FORMULAIRE DE CONNEXION ---
    username = input("Pseudo : ").strip()
    password = input("Mot de passe : ").strip()
    
    if not username or not password:
        print("Erreur : Champs vides.")
        return

    # Hachage du mot de passe (SHA-256)
    # On n'envoie jamais le mot de passe en clair
    pwd_hash = hashlib.sha256(password.encode('utf-8')).digest()

    signer = get_signer(username)
    client_pk_dil = signer.public_key

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT))
        except:
            print("Serveur introuvable.")
            return

        try:
            # 1. Recevoir PK Kyber
            server_pk_kyber = recv_data(s)
            if not server_pk_kyber: return

            # 2. Envoyer IDENTIFIANTS
            send_data(s, username.encode('utf-8'))
            send_data(s, pwd_hash) # <--- Envoi du Hash
            
            # 3. Envoyer Clé Publique
            send_data(s, client_pk_dil)

            # 4. Crypto Post-Quantique
            kem_ct, shared_secret = client_encapsulate(server_pk_kyber)
            aes_key = derive_aes_key(shared_secret)
            sig = signer.sign(kem_ct)
            
            send_data(s, kem_ct)
            send_data(s, sig)
            
        except ConnectionAbortedError:
            print(f"\n[ACCÈS REFUSÉ] Pseudo pris ou mot de passe incorrect.")
            return
        except Exception:
            print("Erreur de connexion.")
            return
        
        print(f"[INFO] Connecté en tant que {username}.")
        threading.Thread(target=receive_loop, args=(s, aes_key), daemon=True).start()

        print("Chattez maintenant :")
        while True:
            try:
                msg = input("> ")
                if msg == "/quit": break
                nonce, ct, tag = encrypt_aes_gcm(aes_key, msg.encode('utf-8'))
                send_data(s, nonce + ct + tag)
            except: break

if __name__ == "__main__":
    run_client()