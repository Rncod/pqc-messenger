# server.py
import socket
import struct
import threading
from crypto.kem import ServerKEM
from crypto.signature import verify_signature
from crypto.symmetric import derive_aes_key, decrypt_aes_gcm, encrypt_aes_gcm

HOST = "0.0.0.0"
PORT = 5000

# Base de données : { "alice": { "key": b'...', "pwd_hash": b'...' } }
USER_DB = {}
db_lock = threading.Lock()

clients_lock = threading.Lock()
connected_clients = {}

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
        try:
            packet = sock.recv(n - len(data))
            if not packet: return None
            data += packet
        except: return None
    return data

def broadcast_message(sender_sock, plaintext_msg):
    with clients_lock:
        sockets = list(connected_clients.keys())
    
    for target_sock in sockets:
        if target_sock == sender_sock: continue
        try:
            target_aes_key = connected_clients[target_sock]
            nonce, ct, tag = encrypt_aes_gcm(target_aes_key, plaintext_msg.encode('utf-8'))
            send_data(target_sock, nonce + ct + tag)
        except: pass

def handle_client(conn, addr):
    print(f"[CONNEXION] {addr}")
    server_kem = ServerKEM()
    username = "Inconnu"

    try:
        # 1. Envoi PK Kyber
        send_data(conn, server_kem.public_key)

        # 2. Réception IDENTIFIANTS (Pseudo + Hash du Mot de passe)
        username_bytes = recv_data(conn)
        password_hash = recv_data(conn) # <--- NOUVEAU
        
        if not username_bytes or not password_hash: return
        username = username_bytes.decode('utf-8')

        # 3. Réception Clé Publique
        client_pk_dil = recv_data(conn)
        
        # --- AUTHENTIFICATION FORTE ---
        with db_lock:
            if username in USER_DB:
                user_data = USER_DB[username]
                stored_key = user_data["key"]
                stored_pwd = user_data["pwd_hash"]

                # Vérification 1 : La clé publique (Identity Check)
                if client_pk_dil != stored_key:
                    print(f"⚠ [ALERTE] '{username}' : Clé incorrecte (Usurpation ?).")
                    return
                
                # Vérification 2 : Le mot de passe (Knowledge Check)
                if password_hash != stored_pwd:
                    print(f"⚠ [ALERTE] '{username}' : Mauvais mot de passe.")
                    return # On coupe la connexion
                
                print(f"[AUTH] '{username}' connecté avec succès.")

            else:
                # Enregistrement nouvel utilisateur
                USER_DB[username] = {
                    "key": client_pk_dil,
                    "pwd_hash": password_hash
                }
                print(f"[NOUVEAU] Utilisateur '{username}' créé et protégé par mot de passe.")

        # 4. Suite du Handshake Post-Quantique
        kem_ct = recv_data(conn)
        sig_kem = recv_data(conn)

        if not verify_signature(client_pk_dil, kem_ct, sig_kem):
            print(f"⚠ [ALERTE] Signature invalide pour {username}.")
            return

        shared_secret = server_kem.decapsulate(kem_ct)
        aes_key = derive_aes_key(shared_secret)

        with clients_lock:
            connected_clients[conn] = aes_key

        msg = f"Serveur : {username} a rejoint le chat."
        broadcast_message(conn, msg)

        # Boucle de messages
        while True:
            packet = recv_data(conn)
            if not packet: break
            if len(packet) < 28: continue
            
            nonce = packet[:12]
            ct = packet[12:-16]
            tag = packet[-16:]

            plaintext = decrypt_aes_gcm(aes_key, nonce, ct, tag)
            final_msg = f"{username} : {plaintext.decode('utf-8')}"
            print(final_msg)
            broadcast_message(conn, final_msg)

    except Exception as e:
        print(f"[ERREUR] {e}")
    finally:
        with clients_lock:
            if conn in connected_clients: del connected_clients[conn]
        conn.close()

def run_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"[SERVEUR SÉCURISÉ] En attente de clients sur {PORT}...")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    run_server()