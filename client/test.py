from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh

# Paramètres pour le groupe 2048-bit de RFC 3526
p = int('E' * 256, 16)  # La valeur hexadécimale de p pour le groupe 2048-bit, à remplacer par la valeur exacte
g = 2

# Créer des paramètres DH avec p et g
parameters = dh.DHParameterNumbers(p, g).parameters(default_backend())
print(parameters)
# Génération d'une clé privée pour l'échange
private_key = parameters.generate_private_key()

