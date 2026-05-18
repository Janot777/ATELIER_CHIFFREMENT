# Atelier – Chiffrement/Déchiffrement (Python `cryptography`) dans GitHub Codespaces

## 1) Lancer le projet dans Codespaces
- Fork / clone ce repo
- Bouton **Code** → **Create codespace on main**

## 2) Installer la bibliothèque Python Cryptographie
```bash
pip install -r requirements.txt
```
## 3) Partie A – Chiffrer/Déchiffrer un texte
```
python app/fernet_demo.py
```
**Quel est le rôle de la clé Fernet ?**  
La clé Fernet est une clé symétrique secrète de 256 bits encodée en Base64, utilisée pour chiffrer et authentifier les données avec AES et HMAC issue de la bibliothèque python cryptography. Un token Fernet (c'est à dire le résultat chiffré) contient :  
```
| Version | Timestamp | IV | Ciphertext | HMAC |
```
* Version (1 octet) : Valeur actuelle : 0x80
* Timestamp (8 octets) : Permet l'expiration des tokens
* IV (16 octets) : Généré aléatoirement - Garantit que deux messages identiques produisent des ciphertexts différents
* Ciphertext (variable) : Résultat du chiffrement AES-128-CBC qui contient les données
* HMAC (32 octets) : Protège contre toute modification
  
## 4) Partie B – Chiffrer/Déchiffrer un fichier
Créer un fichier de test :  
```
echo "Message Top secret !" > secret.txt
```
Chiffrer :
```
python app/file_crypto.py encrypt secret.txt secret.enc
```
Déchiffrer :
```
python app/file_crypto.py decrypt secret.enc secret.dec.txt
cat secret.dec.txt
```
**Que se passe-t-il si on modifie un octet du fichier chiffré ?**  
Le déchiffrement échoue immédiatement avec une exception `cryptography.fernet.InvalidToken`. Aucun contenu (même partiel) n'est restitué. C'est le HMAC (32 octets de fin de token) qui détecte la moindre altération : il est recalculé à partir de la version, du timestamp, de l'IV et du ciphertext, puis comparé en temps constant à celui présent dans le token. Toute différence – y compris un seul bit modifié – invalide le token. Cette propriété d'**authenticité** est aussi importante que la confidentialité : sans elle, un attaquant pourrait modifier le ciphertext sans être détecté.

**Pourquoi ne faut-il pas commiter la clé dans Git ?**  
- **Historique permanent** : un commit pousse la clé dans l'historique Git. Même supprimée plus tard, elle reste accessible via `git log`, `git show`, ou les forks/clones existants. La seule remédiation correcte est de **considérer la clé comme compromise et la révoquer/rotater**.
- **Diffusion incontrôlée** : un repo public expose la clé au monde entier. Un repo privé l'expose à tous les contributeurs (présents et futurs), aux intégrations CI/CD, aux outils de scan, aux sauvegardes, etc.
- **Bots et scanners** : GitHub et de nombreux acteurs malveillants scannent en continu les commits publics à la recherche de secrets ; une clé commitée est généralement exploitée en quelques minutes.
- **Principe de séparation** : le code décrit *comment* chiffrer, les secrets fournissent *avec quoi*. Mélanger les deux empêche de déployer le même code dans plusieurs environnements (dev/staging/prod) avec des clés différentes.
- **Bonne pratique** : stocker la clé dans une variable d'environnement, un **GitHub Repository Secret**, un coffre type Vault/AWS KMS/GCP Secret Manager, et ignorer les fichiers locaux (`.gitignore`).

## 5) Atelier 1 :
Dans cet atelier, la clé Fernet n'est plus générée dans le code mais stockée dans un Repository Secret Github. Ecrivez un nouveau programme **python app/fernet_atelier1.py** qui utilisera une clé Fernet caché dans un Secret GitHub pour encoder et décoder vos fichiers.

### Mise en place
1. Génère une clé Fernet :
   ```bash
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```
2. Dans GitHub : **Settings → Secrets and variables → Actions → New repository secret**  
   Nom : `FERNET_KEY` — Valeur : la clé générée.
3. Le programme `app/fernet_atelier1.py` lit la clé via `os.environ["FERNET_KEY"]`.
   Pour démontrer le bout-en-bout en CI, créer le fichier `.github/workflows/atelier1.yml` (via l'interface GitHub : *Actions → New workflow → set up a workflow yourself*) avec le contenu suivant :

   ```yaml
   name: Atelier 1 — Fernet via GitHub Secret

   on:
     workflow_dispatch:
     push:
       branches: [main]
       paths:
         - "app/fernet_atelier1.py"
         - ".github/workflows/atelier1.yml"
         - "requirements.txt"

   permissions:
     contents: read

   jobs:
     encrypt-decrypt-roundtrip:
       runs-on: ubuntu-latest
       env:
         FERNET_KEY: ${{ secrets.FERNET_KEY }}
       steps:
         - uses: actions/checkout@v4
         - uses: actions/setup-python@v5
           with:
             python-version: "3.12"
             cache: pip
         - run: pip install -r requirements.txt
         - name: Fail fast if secret is missing
           run: |
             if [ -z "${FERNET_KEY}" ]; then
               echo "::error::Le secret FERNET_KEY n'est pas défini sur ce repo."
               exit 1
             fi
             echo "✅ FERNET_KEY présent (longueur=${#FERNET_KEY})."
         - run: echo "Message Top secret depuis GitHub Actions" > secret.txt
         - run: python app/fernet_atelier1.py encrypt secret.txt secret.enc
         - run: python app/fernet_atelier1.py decrypt secret.enc secret.dec.txt
         - run: diff -q secret.txt secret.dec.txt && echo "✅ Round-trip Fernet OK"
   ```

### Utilisation locale (avec variable d'environnement)
```bash
export FERNET_KEY="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
echo "Message Top secret !" > secret.txt
python app/fernet_atelier1.py encrypt secret.txt secret.enc
python app/fernet_atelier1.py decrypt secret.enc secret.dec.txt
cat secret.dec.txt
```

## 6) Atelier 2 :
Les bibliothèques qui proposent un système complet, sûr par défaut et simple d’usage comme Fernet de la bibliothèse Cryptographie sont relativement rares. Toutefois, la bibliothèque PyNaCl via l'outil SecretBox est une très bonne alternative. **travail demandé :** Construire une solution de chiffrement/déchiffrement basé sur l'outils SecretBox de la bibliothèque PyNaCl.

### Implémentation
`app/secretbox_crypto.py` propose :
- `generate-key` : génère une clé secrète de 32 octets (256 bits) encodée Base64.
- `encrypt <in> <out>` : chiffre un fichier avec **XSalsa20-Poly1305** (nonce aléatoire 24 octets préfixé au ciphertext).
- `decrypt <in> <out>` : déchiffre et vérifie le tag d'authentification Poly1305 ; toute altération lève `nacl.exceptions.CryptoError`.

La clé est lue depuis la variable d'environnement `NACL_KEY` (Base64), exactement comme la clé Fernet de l'Atelier 1 — donc également stockable dans un **GitHub Repository Secret**.

### Utilisation
```bash
pip install -r requirements.txt
export NACL_KEY="$(python app/secretbox_crypto.py generate-key)"
echo "Top secret PyNaCl" > nacl_secret.txt
python app/secretbox_crypto.py encrypt nacl_secret.txt nacl_secret.enc
python app/secretbox_crypto.py decrypt nacl_secret.enc nacl_secret.dec.txt
cat nacl_secret.dec.txt
```

### Comparaison rapide Fernet vs SecretBox
| Critère | Fernet (cryptography) | SecretBox (PyNaCl) |
|---|---|---|
| Algo chiffrement | AES-128-CBC | XSalsa20 |
| Authentification | HMAC-SHA256 | Poly1305 |
| Taille de clé | 32 octets (256 bits) | 32 octets (256 bits) |
| Nonce / IV | 16 octets, dans le token | 24 octets, à fournir/préfixer |
| Timestamp embarqué | Oui (expiration possible) | Non |
| Encodage du token | Base64 (URL-safe) | Binaire brut |
| Bibliothèque sous-jacente | OpenSSL | libsodium |









