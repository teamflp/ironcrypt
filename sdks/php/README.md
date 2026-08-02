# IronCrypt — SDK PHP

Client HTTP pour utiliser **IronCrypt depuis une application PHP** via le démon `ironcryptd`.

PHP n’embarque pas la cryptographie Rust : l’appli envoie les données au démon, qui chiffre / déchiffre avec les clés locales (ou cloud), puis renvoie le résultat.

```text
┌─────────────┐     HTTP + Bearer      ┌──────────────┐
│  App PHP    │ ─────────────────────► │  ironcryptd  │
│ IronCrypt   │  POST /write  (chiffrer)│  + clés PEM │
│ Client      │  POST /read   (déchiffrer)└──────────────┘
└─────────────┘
```

## À quoi sert `IronCryptClient` ?

La classe `IronCrypt\Sdk\IronCryptClient` encapsule Guzzle et expose deux méthodes :

| Méthode PHP | Endpoint daemon | Permission API | Effet |
| --- | --- | --- | --- |
| `encrypt($data, $apiKey, $password = null)` | `POST /write` | `write` | Chiffre le corps, renvoie des **octets binaires** |
| `decrypt($data, $apiKey, $password = null)` | `POST /read` | `read` | Déchiffre le corps, renvoie le **plaintext** |

L’authentification se fait avec l’en-tête :

```http
Authorization: Bearer <clé_api_secrète_base64>
```

La clé secrète est celle affichée par `ironcrypt generate-api-key` — **à envoyer telle quelle** (déjà en base64). Ne la re-encodez pas.

En-tête optionnel : `X-Password` (3ᵉ argument de `encrypt` / `decrypt`) pour un gate Argon2 supplémentaire sur le payload.

## Prérequis

1. **PHP ≥ 7.4** et [Composer](https://getcomposer.org/)
2. Le démon **`ironcryptd`** démarré et joignable (souvent `http://127.0.0.1:3000`)
3. Une **clé API** enregistrée dans `keys.json` (hash) avec au moins `write` et/ou `read`
4. Des clés crypto (`keys/private_key_v1.pem`, `keys/public_key_v1.pem`) — ex. via `make bootstrap-lab`

## Installation du SDK

Depuis ce dossier :

```bash
cd sdks/php
composer install
```

Cela crée `vendor/` (gitignored). **Sans cette étape**, l’IDE signale souvent `Undefined type 'GuzzleHttp\Client'`.

### Dans un projet Composer existant

Option path repository (développement local) dans le `composer.json` de votre app :

```json
{
  "repositories": [
    {
      "type": "path",
      "url": "../ironcrypt/sdks/php"
    }
  ],
  "require": {
    "ironcrypt/sdk": "*"
  }
}
```

Puis `composer update ironcrypt/sdk`.

## Démarrer le démon (rappel)

```bash
# À la racine du dépôt IronCrypt
cargo build --release
make bootstrap-lab

./target/release/ironcrypt generate-api-key
# 1) Copier le HASH → keys.json (champ "keyHash", camelCase)
# 2) Garder la clé secrète base64 pour PHP (variable d'environnement)

./target/release/ironcryptd \
  --host 127.0.0.1 --port 3000 \
  --key-directory keys --key-version v1 \
  --api-keys-file keys.json \
  --config ironcrypt.toml
```

Exemple d’entrée `keys.json` :

```json
[
  {
    "description": "Backend PHP",
    "keyHash": "HASH_HEX_SHA512",
    "permissions": ["write", "read"]
  }
]
```

## Exemple complet

```php
<?php

require_once __DIR__ . '/vendor/autoload.php';

use IronCrypt\Sdk\IronCryptClient;
use GuzzleHttp\Exception\RequestException;

$client = new IronCryptClient(
    getenv('IRONCRYPT_URL') ?: 'http://127.0.0.1:3000'
);
$apiKey = getenv('IRONCRYPT_API_KEY');
if (!$apiKey) {
    fwrite(STDERR, "Définir IRONCRYPT_API_KEY (clé secrète base64)\n");
    exit(1);
}

$original = 'données sensibles depuis PHP';

try {
    // Chiffrer
    $ciphertext = $client->encrypt($original, $apiKey);
    // Stocker $ciphertext en BLOB / base64 en base de données…
    $stored = base64_encode($ciphertext);

    // Déchiffrer plus tard
    $plain = $client->decrypt(base64_decode($stored), $apiKey);
    assert($plain === $original);
    echo "OK: round-trip réussi\n";

    // Optionnel : mot de passe Argon2
    $sealed = $client->encrypt($original, $apiKey, 'Str0ngP@ssw0rd42!');
    $opened = $client->decrypt($sealed, $apiKey, 'Str0ngP@ssw0rd42!');
    assert($opened === $original);
} catch (RequestException $e) {
    $status = $e->hasResponse() ? $e->getResponse()->getStatusCode() : 0;
    // 401 = clé invalide, 403 = permission, 429 = rate limit, 400 = crypto / mauvais password
    fwrite(STDERR, "HTTP {$status}: " . $e->getMessage() . "\n");
    exit(1);
}
```

## Appel sans le SDK (cURL brut)

```php
<?php
$apiKey = getenv('IRONCRYPT_API_KEY');
$data = 'hello';

$ch = curl_init('http://127.0.0.1:3000/write');
curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_HTTPHEADER => [
        "Authorization: Bearer {$apiKey}",
        'Content-Type: application/octet-stream',
    ],
    CURLOPT_POSTFIELDS => $data,
    CURLOPT_RETURNTRANSFER => true,
]);
$encrypted = curl_exec($ch);
$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($code !== 200) {
    throw new RuntimeException("write failed: HTTP {$code}");
}
```

## Bonnes pratiques

- Stocker `IRONCRYPT_API_KEY` dans l’environnement / un secret manager, **jamais** en dur dans le code.
- Préférer `127.0.0.1` ou un réseau privé ; hors loopback, activer le TLS du démon (`--tls-cert` / `--tls-key`).
- Les réponses `/write` sont **binaires** : en SQL, utilisez un BLOB ou `base64_encode` avant un champ texte.
- Permissions minimales : une clé `write` seule pour un job d’ingestion ; `read` seul pour un worker de lecture.
- Ne pas committer `keys.json`, `ironcrypt.toml`, ni les PEM (uniquement les `*.example`).

## Alternatives (si vous n’utilisez pas le démon)

| Approche | Intérêt |
| --- | --- |
| **SDK + `ironcryptd`** (ce README) | Recommandé pour les apps PHP web |
| **CLI** (`exec` / `proc_open` sur `ironcrypt`) | Scripts ponctuels ; éviter en requête HTTP |
| **FFI** (`libironcrypt` + `ironcrypt.h`) | Processus sans démon ; voir `FFI_EXAMPLES.md` |

## Dépannage

| Symptôme | Cause probable |
| --- | --- |
| `Undefined type 'GuzzleHttp\Client'` | `composer install` non exécuté dans `sdks/php` |
| HTTP `401` | Mauvaise clé Bearer, ou hash absent / incorrect dans `keys.json` |
| HTTP `403` | Permission manquante (`write` / `read`) |
| HTTP `429` | Rate limit du démon |
| Connection refused | `ironcryptd` non démarré ou mauvaise URL |
