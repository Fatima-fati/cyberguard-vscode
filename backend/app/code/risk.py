"""Evaluation du risque d'un finding de code.

Meme philosophie que `app.ai.risk_assessment` pour les alertes Wazuh : le
backend calcule un score **deterministe et explicable**, facteur par
facteur. En phase 3, l'avis du modele sera fusionne a ce score par
`app.ai.risk_assessment.fuse()`, qui detient les poids du projet
(60 % modele / 40 % backend) et n'est donc pas redefini ici.
"""

import logging
import re
from typing import Optional

from app.ai.risk_assessment import fuse
from app.ai.schemas import RiskFactor, Severity, band_for_score, severity_for_score
from app.code.schemas import RuleHit

logger = logging.getLogger(__name__)

# Contribution de la severite de base de la regle.
SEVERITY_POINTS: dict[str, int] = {
    "CRITICAL": 60,
    "HIGH": 45,
    "MEDIUM": 28,
    "LOW": 12,
}

# Fichiers dont une faiblesse porte plus loin que la moyenne.
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?i)(auth|login|session|password|credential|token|payment|billing|"
    r"admin|security|crypto|config|settings|middleware|permission)"
)

# Fichiers de test : une faiblesse y est reelle mais rarement exposee.
TEST_PATH_PATTERN = re.compile(
    r"(?i)(^|[/\\])(tests?|spec|__tests__|fixtures?|examples?|samples?)[/\\]"
    r"|(^|[/\\])(test_|_test\.|\.test\.|\.spec\.)"
)

# Indices qu'une entree utilisateur atteint la ligne concernee.
USER_INPUT_PATTERN = re.compile(
    r"(?i)\b(request|req\.|params|query|body|form|input|argv|"
    r"\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|getParameter|user_input|"
    r"payload|headers)\b"
)


def compute_baseline(
    hit: RuleHit,
    file_path: str = "",
    hits_in_file: int = 1,
) -> tuple[int, list[RiskFactor]]:
    """Score deterministe (0-100) d'un finding, et facteurs qui l'expliquent.

    Aucun facteur n'est compte sans donnee correspondante : le score reste
    justifiable ligne par ligne devant le developpeur.
    """
    factors: list[RiskFactor] = []

    severity_points = SEVERITY_POINTS.get(hit.base_severity, SEVERITY_POINTS["MEDIUM"])
    score = severity_points
    factors.append(
        RiskFactor(
            name="Gravité de la règle",
            detail=f"règle {hit.rule_id} classée {hit.base_severity}",
            weight=severity_points,
        )
    )

    # Une regex tres specifique merite plus de credit qu'un motif large.
    confidence_points = int(round((hit.rule_confidence - 0.5) * 20))
    if confidence_points:
        score += confidence_points
        factors.append(
            RiskFactor(
                name="Précision du motif",
                detail=(
                    f"confiance du motif : {int(hit.rule_confidence * 100)} %"
                ),
                weight=confidence_points,
            )
        )

    if file_path and SENSITIVE_PATH_PATTERN.search(file_path):
        score += 10
        factors.append(
            RiskFactor(
                name="Fichier sensible",
                detail="le chemin évoque l'authentification, la configuration "
                "ou le paiement",
                weight=10,
            )
        )

    if file_path and TEST_PATH_PATTERN.search(file_path):
        score -= 15
        factors.append(
            RiskFactor(
                name="Fichier de test",
                detail="code de test : exposition en production peu probable",
                weight=-15,
            )
        )

    snippet = hit.location.snippet or ""
    if USER_INPUT_PATTERN.search(snippet):
        score += 12
        factors.append(
            RiskFactor(
                name="Entrée utilisateur",
                detail="une donnée issue de la requête apparaît sur la ligne",
                weight=12,
            )
        )

    if hits_in_file >= 5:
        score += 5
        factors.append(
            RiskFactor(
                name="Accumulation",
                detail=f"{hits_in_file} findings dans le même fichier",
                weight=5,
            )
        )

    return max(0, min(100, score)), factors


def assess(
    hit: RuleHit,
    file_path: str = "",
    hits_in_file: int = 1,
) -> tuple[int, Severity, str, list[RiskFactor], float]:
    """Evalue un finding **sans IA** (phase 1).

    Retourne (score, severite, libelle du niveau, facteurs, confiance).
    La confiance renvoyee est celle du motif : elle dit ce qu'elle vaut,
    et n'est jamais presentee comme le verdict d'une analyse.
    """
    baseline, factors = compute_baseline(hit, file_path, hits_in_file)
    severity = severity_for_score(baseline)

    # Un motif tres sur ne doit pas etre degrade sous la severite prevue
    # par la regle ; a l'inverse, le score peut aggraver le diagnostic.
    severity = _at_least(severity, hit.base_severity, baseline)

    return baseline, severity, band_for_score(baseline), factors, hit.rule_confidence


def assess_with_model(
    hit: RuleHit,
    model_score: int,
    model_risk_factors: list[str],
    file_path: str = "",
    hits_in_file: int = 1,
) -> tuple[int, str, str, list[RiskFactor]]:
    """Fusion score deterministe + avis du modele. **Inutilise en phase 1.**

    Prepare la phase 3 : les poids viennent de `app.ai.risk_assessment`,
    definis une seule fois pour tout le projet.
    """
    baseline, factors = compute_baseline(hit, file_path, hits_in_file)
    return fuse(model_score, model_risk_factors, baseline, factors)


_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _at_least(computed: str, floor: str, score: int) -> Severity:
    """Le score ne descend jamais une regle sous sa gravite annoncee.

    Une regle CRITICAL dont le score tombe a 55 resterait affichee MEDIUM,
    ce qui contredirait le catalogue expose par /api/code/rules. Le
    plancher n'est cependant applique que si le motif est credible.
    """
    if _ORDER.get(computed, 0) >= _ORDER.get(floor, 0):
        return computed  # type: ignore[return-value]
    if score <= 20:
        # Score tres bas (fichier de test, motif large) : on laisse le
        # calcul parler plutot que d'imposer le plancher.
        return computed  # type: ignore[return-value]
    return floor  # type: ignore[return-value]
