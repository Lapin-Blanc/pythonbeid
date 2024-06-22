
# PythonBEID

PythonBEID est un module Python pour lire les informations essentielles des cartes d'identité belge à l'aide d'un lecteur de cartes et de la bibliothèque `pyscard`.

## Installation

Vous pouvez installer ce module via pip :

```bash
pip install pythonbeid
```

## Utilisation

Voici un exemple simple d'utilisation du module `pythonbeid` pour lire les informations d'une carte :

```python
from pythonbeid.card_reader import CardReader
from pprint import pprint

def main():
    try:
        cr = CardReader()
        informations = cr.read_informations(photo=False)
        pprint(informations)
    except RuntimeError as e:
        print(f"Erreur: {e}")

if __name__ == "__main__":
    main()
```

## Dépendances

Ce module nécessite la bibliothèque suivante :
- `pyscard`

Vous pouvez installer les dépendances avec pip :

```bash
pip install -r requirements.txt
```

## Tests

Les tests unitaires sont situés dans le répertoire `tests`. Vous pouvez exécuter les tests avec `unittest` :

```bash
python -m unittest discover -s tests
```

## Contribuer

Les contributions et améliorations sont les bienvenues !

## Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.
