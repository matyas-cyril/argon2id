# argon2id

## Description
Permet de générer et de vérifier un hash de mot de passe de type Argon2id.

## Index
- [Installation](#installation)
- [Paramètres](#paramètres)
- [Exemples](#exemples)

## Installation

```bash
go get github.com/matyas-cyril/argon2id
```
*[Retour Index](#index)*

## Paramètres

| **CLEF** | **TYPE** | **MIN** | **MAX** | **DÉFAUT** | **DESCRIPTION** |
|:---------|:--------:|:-------:|:-------:|:----------:|:----------------|
| `m` | uint8 | 1 | 4096 | 32 | Mémoire utilisée par l'algorithme en Mo.<br>Une mémoire plus élevée augmente la sécurité, mais exige plus de ressources.<br>Elle est transformée en ko pour le traitement et pour le rendu du hash. |
| `t` | uint32| 1 | 20 | 3 | Nombre d'itérations.<br>Plus d'itérations ralentissent la fonction de hachage, rendant les attaques par force brute plus difficiles. |
| `p` | uint8 | 1 | 128 | 4 | Combien de threads peuvent effectuer les calculs en parallèle. Une valeur plus élevée permet une exécution plus rapide sur des systèmes multi-cœurs. |
| `saltLength` | uint8 | 16 | 64 | 16 | Nombre d'octets du salt lors de l'autogénération |
| `hashLength` | uint32 | 16 | 128 | 32 | Nombre d'octets du hash.<br>Une longueur de hachage plus longue fournit une meilleure sécurité contre les collisions. |

La personnalisation des paramètres est possible via la fonction `Params` avec les clefs définies dans le tableau ci-dessus.

*[Retour Index](#index)*

## DefaultParams

Constante contenant les valeurs par défaut.  
L'ensemble des valeurs est disponible [ici](#paramètres).

Si le nombre de coeurs logiques est inférieur à 4 alors p=1.

*[Retour Index](#index)*

## Exemples
Voir le fichier : argon2id_test.go

*[Retour Index](#index)*
