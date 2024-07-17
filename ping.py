import socket, struct, array, time, select

"""
Type            |Minimum |Maximum
----------------+--------+-------
short           | -32 767| 32 767
unsigned short  |       0| 65 535

"""
# Créer un socket RAW pour ICMP
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)


# Champs du paquet ICMP
icmp_type = 8  # Echo Request Type (8 bits)
icmp_code = 0  # Code (8 bits)
icmp_checksum = 0  # Checksum (16 bits) calculer plus tard
icmp_identifier = 1  # Identifier (16 bits)
icmp_sequence_number = 1  # Sequence Number (16 bits)
icmp_data = b"onditpainauchocolat"  # Data (variable)


# Construire le paquet sans le checksum
header = struct.pack(
    "bbHHh",  # b=8bits, H=16bits , h=16bits
    icmp_type,  # b
    icmp_code,  # b
    icmp_checksum,  # H (0 à 65535 = unsigned short)
    icmp_identifier,  # H (0 à 65535 = unsigned short)
    icmp_sequence_number,  # h (-32767 à 32767 = short)
)
packet_without_checksum = header + icmp_data


def checksum(data):
    """
    Calcule le checksum pour vérifier l'intégrité des données.

    Cette fonction prend une séquence de données binaires et retourne un checksum de 16 bits.

    Étapes du calcul :
    1. Si le nombre d'octets est impair, ajoute un octet nul pour rendre la longueur paire.
    2. Additionne les paires de 16 bits.
    3. Ajoute les bits de dépassement.
    4. Inverse les bits de la somme pour obtenir le checksum.

    Args:
        data (bytes): Données binaires pour lesquelles calculer le checksum.

    Returns:
        int: Le checksum de 16 bits.
    """

    # Gestion des données impaires
    if len(data) % 2:
        data += b"\0"

    # Utilisation d'array pour les additions
    s = sum(array.array("H", data))

    # Addition des bits de dépassement
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16

    # Retour du checksum
    return ~s & 0xFFFF


# Calculer le checksum du paquet
icmp_checksum = checksum(packet_without_checksum)

# Reconstruire le paquet avec le checksum
header_with_checksum = struct.pack(
    "bbHHh",  # b=8bits, H=16bits, h=16bits
    icmp_type,  # b
    icmp_code,  # b
    icmp_checksum,  # H (0 à 65535 = unsigned short)
    icmp_identifier,  # H (0 à 65535 = unsigned short)
    icmp_sequence_number,  # h (-32767 à 32767 = short)
)
packet = header_with_checksum + icmp_data

# Affichage du paquet
print(packet)

# ///////////////////////////////////////////////////////////////////////

# Adresse de destination
destination_address = "1.1.1.1"

# Envoi du paquet
s.sendto(
    packet, (destination_address, 1)
)  # Numéro de port : 1 (non pertinent pour ICMP)

# Enregistre l'heure de départ pour mesurer le temps de réponse
start_time = time.time()

# Temps d'attente pour une réponse (en secondes)
timeout = 1

# Boucle pour attendre la réponse
while True:
    # Utilisation de select pour attendre la réponse avec un timeout
    ready = select.select([s], [], [], timeout)

    # Vérifie si le temps d'attente est écoulé sans recevoir de réponse
    if ready[0] == []:
        print("Request timed out.")
        break

    # Enregistre l'heure de réception pour mesurer le temps de réponse
    time_received = time.time()

    # Réception du paquet réponse
    received_packet, addr = s.recvfrom(1024)

    # Extraction de l'en-tête ICMP de la réponse (les 8 octets après l'en-tête IP)
    icmp_header = received_packet[20:28]

    # Dépaquetage de l'en-tête ICMP
    icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq = struct.unpack(
        "bbHHh", icmp_header
    )

    # Vérifie si l'identifiant du paquet reçu correspond à celui envoyé
    if icmp_id == icmp_identifier:
        # Calcul du temps de réponse en millisecondes
        round_trip_time = (time_received - start_time) * 1000

        # Affiche le résultat
        print(f"Received packet from {addr[0]} in {round_trip_time:.2f} ms")
        break
