"""Cote backend du test de contrat (phase 0, recommandation §25.3 de l'audit).

Le risque ferme ici : `backendClient.ts` et les modeles Pydantic decrivent
le meme contrat en deux endroits, sans lien mecanique. Une divergence ne se
voit qu'a l'execution, chez l'utilisateur.

`contract/api-contract.json` fait autorite. Ce test verifie que le schema
OpenAPI que FastAPI genere le respecte ; son pendant TypeScript verifie que
les types de l'extension le respectent aussi. Une divergence d'un cote ou
de l'autre fait echouer un build.

Le test verifie aussi les **interdits** : un champ de contenu de fichier,
un chemin absolu ou un score de securite ajoute par inadvertance a un
modele de projet fait echouer la suite.
"""

import json
from pathlib import Path

import pytest

from app.main import app

CONTRACT_PATH = (
    Path(__file__).resolve().parent.parent.parent / "contract" / "api-contract.json"
)


@pytest.fixture(scope="module")
def contract() -> dict:
    assert CONTRACT_PATH.is_file(), f"Contrat introuvable : {CONTRACT_PATH}"
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def openapi() -> dict:
    return app.openapi()


def schema_properties(openapi: dict, model: str) -> set[str]:
    """Champs declares par un modele dans le schema OpenAPI."""
    schemas = openapi["components"]["schemas"]
    assert model in schemas, (
        f"Modele « {model} » absent du schema OpenAPI. "
        f"Il est nomme dans le contrat : soit il a ete renomme, soit il "
        f"n'est plus utilise par aucune route."
    )
    return set(schemas[model].get("properties", {}))


# --------------------------------------------------------------------------
# Les routes du contrat existent, avec la bonne methode
# --------------------------------------------------------------------------


def test_toutes_les_routes_du_contrat_existent(contract, openapi):
    paths = openapi["paths"]

    for endpoint in contract["endpoints"]:
        method, path = endpoint.split(" ", 1)
        assert path in paths, f"Route « {path} » absente du backend"
        assert method.lower() in paths[path], (
            f"Route « {path} » n'accepte pas {method}"
        )


# --------------------------------------------------------------------------
# Les modeles portent les champs attendus
# --------------------------------------------------------------------------


def test_les_modeles_de_requete_portent_les_champs_attendus(contract, openapi):
    for endpoint, definition in contract["endpoints"].items():
        request = definition.get("request")
        if not request:
            continue

        declared = schema_properties(openapi, request["model"])
        for field in request.get("required", []):
            assert field in declared, (
                f"{endpoint} : le champ « {field} » manque a "
                f"{request['model']}. Le contrat et le backend ont divergé."
            )


def test_les_modeles_de_reponse_portent_les_champs_attendus(contract, openapi):
    for endpoint, definition in contract["endpoints"].items():
        response = definition.get("response")
        if not response:
            continue

        declared = schema_properties(openapi, response["model"])
        for field in response.get("required", []):
            assert field in declared, (
                f"{endpoint} : le champ « {field} » manque a "
                f"{response['model']}. Le contrat et le backend ont divergé."
            )


def test_les_modeles_nommes_portent_les_champs_attendus(contract, openapi):
    for model, definition in contract["models"].items():
        declared = schema_properties(openapi, model)
        for field in definition.get("required", []):
            assert field in declared, (
                f"Le champ « {field} » manque a {model}."
            )


# --------------------------------------------------------------------------
# Les interdits — la partie securite du contrat
# --------------------------------------------------------------------------


def test_aucun_champ_interdit_n_apparait_dans_un_modele(contract, openapi):
    """Un champ interdit ajoute par inadvertance fait echouer le build.

    Ce n'est pas une precaution theorique : la facilite, quand une phase
    suivante aura besoin du contenu d'un fichier, sera de l'ajouter au
    modele existant. Ce test transforme cette facilite en echec visible,
    qui oblige a decider plutot qu'a laisser glisser.
    """
    for model, definition in contract["models"].items():
        declared = schema_properties(openapi, model)
        for field in definition.get("forbidden", []):
            assert field not in declared, (
                f"Le champ « {field} » est apparu dans {model}. "
                f"Il est explicitement interdit par le contrat : "
                f"{definition.get('purpose', '')}"
            )


def test_aucun_champ_interdit_n_apparait_dans_une_requete(contract, openapi):
    for endpoint, definition in contract["endpoints"].items():
        request = definition.get("request")
        if not request:
            continue
        declared = schema_properties(openapi, request["model"])
        for field in request.get("forbidden", []):
            assert field not in declared, (
                f"{endpoint} : le champ interdit « {field} » est apparu dans "
                f"{request['model']}."
            )


def test_aucun_modele_de_projet_ne_porte_de_contenu_de_fichier(openapi):
    """Balayage large, au-dela de la liste nominative du contrat.

    Un champ nomme autrement mais de meme nature — `raw_text`,
    `file_body` — serait manque par la liste. Ce test cherche le motif.
    """
    suspects = ("content", "body", "text", "raw", "source_code", "excerpt")
    # `content_hash` est legitime : c'est une empreinte, pas un contenu.
    autorises = {"content_hash"}

    schemas = openapi["components"]["schemas"]
    modeles_projet = [
        name
        for name in schemas
        if name.startswith(("Project", "Indexed", "Classified", "Detected", "Manifest", "Git", "File"))
    ]
    assert modeles_projet, "Aucun modele de projet trouve : test inoperant"

    for name in modeles_projet:
        for field in schemas[name].get("properties", {}):
            if field in autorises:
                continue
            for suspect in suspects:
                assert suspect not in field.lower(), (
                    f"{name}.{field} ressemble a un champ de contenu. "
                    f"Le contexte de projet ne transporte que des "
                    f"metadonnees."
                )


def test_aucun_modele_de_projet_ne_porte_de_chemin_absolu(openapi):
    schemas = openapi["components"]["schemas"]
    interdits = ("workspace_path", "root_path", "absolute_path", "fs_path")

    for name, schema in schemas.items():
        if not name.startswith(("Project", "Indexed", "Classified")):
            continue
        for field in schema.get("properties", {}):
            assert field.lower() not in interdits, (
                f"{name}.{field} porterait un chemin absolu. Seul "
                f"`root_hash` circule."
            )


# --------------------------------------------------------------------------
# Perimetre d'authentification
# --------------------------------------------------------------------------


def test_le_health_du_code_est_la_seule_route_publique_annoncee(contract):
    """Le contrat doit refleter le perimetre reel de l'authentification."""
    publiques = [
        endpoint
        for endpoint, definition in contract["endpoints"].items()
        if definition.get("authenticated") is False
    ]
    assert publiques == ["GET /api/code/health"]


def test_les_routes_sensibles_du_contrat_refusent_un_appel_anonyme(contract):
    """Le contrat annonce `authenticated: true` : on le verifie vraiment.

    Sans cette verification, le contrat pourrait affirmer une protection
    que le code n'applique pas — exactement le genre d'affirmation sans
    preuve que le projet s'interdit.
    """
    from fastapi.testclient import TestClient

    with TestClient(app) as anonyme:
        for endpoint, definition in contract["endpoints"].items():
            if not definition.get("authenticated"):
                continue
            method, path = endpoint.split(" ", 1)
            # Les parametres de chemin sont remplaces par une valeur quelconque :
            # un 401 doit precéder toute recherche en base.
            concrete = path.replace("{project_uid}", "peu-importe")
            response = anonyme.request(method, concrete, json={})
            assert response.status_code == 401, (
                f"{endpoint} est annonce authentifie mais repond "
                f"{response.status_code} sans jeton."
            )


# --------------------------------------------------------------------------
# Le contrat lui-meme reste coherent
# --------------------------------------------------------------------------


def test_le_contrat_est_bien_forme(contract):
    assert contract["version"]
    assert contract["endpoints"]
    assert contract["models"]
    assert contract["invariants"]

    for endpoint in contract["endpoints"]:
        method, _, path = endpoint.partition(" ")
        assert method in {"GET", "POST", "PUT", "DELETE", "PATCH"}, endpoint
        assert path.startswith("/api/"), endpoint
