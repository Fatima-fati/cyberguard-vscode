"""Analyse de securite du code source envoye par l'extension VS Code.

Ce paquet est independant de la chaine Wazuh (`app.poller`,
`app.wazuh_client`, `app.ai.notifications`) : il ne lit ni n'ecrit aucune
de ses tables. Il reutilise en revanche les briques transverses du projet
(`app.ai.openai_client`, `app.ai.sanitizer`, `app.ai.schemas`, `app.i18n`,
`app.store`) pour ne pas dupliquer de logique.

Phase 1 : detection deterministe uniquement. Aucun appel a OpenAI.
"""
