"""Moteur de securite projet : secrets, dependances, vulnerabilites.

**Aucun code de ce paquet n'appelle Wazuh.** Ni le Manager, ni l'Indexer,
ni l'API Wazuh : la detection de secrets, l'inventaire des dependances et
l'analyse de vulnerabilites fonctionnent avec Wazuh completement arrete ou
absent. La seule sortie reseau possible est celle du fournisseur de
vulnerabilites (OSV), et elle est bornee, configurable et coupable.

Principe tenu partout : **le moteur deterministe est la source de verite.**
Une IA pourra plus tard expliquer et contextualiser une preuve ; elle ne
decide jamais qu'un secret ou une vulnerabilite existe.
"""
