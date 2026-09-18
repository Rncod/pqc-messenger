# crypto/kem.py

"""
KEM post-quantique basé sur ML-KEM (CRYSTALS-Kyber) via la lib kyber-py.

Utilisation de l'API officielle :
    >>> from kyber_py.ml_kem import ML_KEM_768
    >>> ek, dk = ML_KEM_768.keygen()
    >>> key, ct = ML_KEM_768.encaps(ek)
    >>> key2 = ML_KEM_768.decaps(dk, ct)
    >>> assert key == key2
"""

from kyber_py.ml_kem import ML_KEM_768


class ServerKEM:
    """
    KEM côté SERVEUR.

    - génère une paire de clés ML-KEM-768 :
        encap_key (publique), decap_key (secrète)
    - expose la clé publique au client
    - permet de décapsuler le ciphertext du client
    """

    def __init__(self) -> None:
        # encap_key = clé publique, decap_key = clé privée pour décapsulation
        self._encap_key, self._decap_key = ML_KEM_768.keygen()

    @property
    def public_key(self) -> bytes:
        """
        Clé publique (encapsulation key) à envoyer au client.
        """
        return self._encap_key

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """
        Décapsule le ciphertext reçu du client et retourne le shared_secret.
        """
        shared_secret = ML_KEM_768.decaps(self._decap_key, ciphertext)
        return shared_secret


def client_encapsulate(server_public_key: bytes) -> tuple[bytes, bytes]:
    """
    Côté CLIENT :
    - prend la clé publique ML-KEM-768 du serveur
    - encapsule un secret
    - renvoie (ciphertext, shared_secret_client)
    """
    shared_secret, ciphertext = ML_KEM_768.encaps(server_public_key)
    return ciphertext, shared_secret
