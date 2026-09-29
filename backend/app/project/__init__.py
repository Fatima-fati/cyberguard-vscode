"""Contexte de securite d'un projet (phase 1).

Ce paquet repond a une seule question : *dans quel projet l'agent
travaille-t-il ?* Il ne detecte aucune vulnerabilite — c'est le role de
`app.code` — et ne parcourt jamais le disque du developpeur : l'extension
decouvre localement et soumet des **metadonnees**, le backend les
normalise, les classe et les conserve.

Repartition des responsabilites, volontairement nette :

    Extension                      Backend (ici)
    ---------                      -------------
    parcourt le disque             ne lit aucun fichier
    lit les manifestes             classe, deduit, persiste
    envoie des metadonnees         tient le contexte
    n'a aucune table de regles     detient toute la connaissance
                                   (langages, frameworks, motifs)

Ce choix suit la regle du projet : la logique de detection reste dans le
backend. L'extension n'embarque ni catalogue de frameworks, ni liste de
motifs sensibles cote contexte — elle ne fait que decrire ce qu'elle voit.
"""
