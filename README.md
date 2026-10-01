# aep-governance

Zentrale Workflows, Rego-Policies und das Regelprofil der AEP-Plattform.
Dieses Repository wird aus dem Ordner `governance/` von `aep-platform` erzeugt
(`uv run tasks.py sync-governance`); Änderungen bitte dort vornehmen.

## Inhalt

| Pfad | Zweck |
| --- | --- |
| `.github/workflows/ci.yml` | Wiederverwendbarer Workflow für Pull Requests mit den Pflicht-Checks `test`, `security`, `policy`, `protected-paths`, `e2e`; dazu der Hilfsjob `policy-plan` |
| `.github/workflows/deploy.yml` | Wiederverwendbarer Workflow nach dem Merge: `build`, `deploy-dev`, `deploy-test`, `e2e-test`, `deploy-prod` |
| `actions/terraform-deploy/` | Gemeinsamer Schritt der Bereitstellung: statische Prüfung, `plan`, Rego-Policies auf genau diesen Plan, `apply` dieses Plans, Rauchtest auf `/healthz` |
| `policies/terraform/` | Rego-Regeln `tags`, `location`, `resource_types`, `storage`, `scale` mit Unit-Tests |
| `policies/fixtures/` | Beispielpläne (`terraform show -json`) für Tests |
| `profiles/demo.yaml` | Regelprofil: alle Schwellen, Listen und Freigeber |
| `scripts/protected_paths.py` | Prüfung geänderter Dateien gegen `agent.protected_paths` (Eröffner und alle Commit-Autoren) |
| `scripts/tf_static_check.py` | Statische Prüfung von `infra/` vor `terraform init` mit echtem HCL-Parser (python-hcl2, Versionen und Hashes in `scripts/requirements-hcl.txt`): nur `azurerm_*`-Typen, `provider "azurerm" { features {} }`, leeres `backend "azurerm" {}`, keine Module, Provisioner, Override-Dateien oder Symlinks; nicht lesbare Dateien werden abgelehnt |
| `scripts/scanner_overrides.py` | Lehnt projekteigene gitleaks-/Trivy-Konfigurationen, `.npmrc` und Inline-Ausnahmen ab |
| `scripts/testdata/poc-bypass/` | Umgehungsversuche aus dem Review als Testfälle |
| `security/` | Zentrale Konfiguration für gitleaks und Trivy |
| `terraform/cli.tfrc` | Terraform-CLI-Konfiguration der Pipeline (`TF_CLI_CONFIG_FILE`): installiert nur `hashicorp/azurerm` |

## Nutzung in einem Projekt

```yaml
jobs:
  ci:
    uses: <org>/aep-governance/.github/workflows/ci.yml@v1
```

Der Aufrufer braucht die Rechte `contents: read`, `id-token: write` und
`pull-requests: write` (für den Kommentar des Checks `policy`). Die Checks heißen
im Pull Request `ci / test`, `ci / security` usw. (Name des aufrufenden Jobs vorangestellt).

Die Workflows lesen Regelprofil, Policies, Skripte und Scanner-Konfiguration aus genau
dem Commit, aus dem sie selbst stammen (`job.workflow_repository`, `job.workflow_sha`).

## Was das Projekt nicht beeinflussen kann

- `policy-plan` erzeugt den Plan mit der Plan-Identität (OIDC), darf aber nicht in den
  Pull Request schreiben. Zwei unabhängige Sperren verhindern fremden Code: die
  statische Prüfung mit HCL-Parser vor `terraform init` und die zentrale
  CLI-Konfiguration, mit der Terraform keinen anderen Provider als azurerm installieren
  kann (dazu eigenes Plugin-Cache-Verzeichnis, `TF_CLI_ARGS*` leer, `-lockfile=readonly`).
  Werte der Plattform werden mit `-var` nach der `-var-file` übergeben und gehen damit vor.
- `policy` führt keinen Projektcode aus: Es liest den Plan als Artefakt, prüft dessen
  SHA-256 gegen die Ausgabe von `policy-plan`, wendet die zentralen Policies an und
  kommentiert den Pull Request. Ohne Azure-Konfiguration schlägt der Check fehl.
- `security` nutzt nur die zentrale Scanner-Konfiguration; projekteigene Konfiguration,
  Ignore-Listen und Inline-Ausnahmen lassen den Check fehlschlagen.
- Bei der Bereitstellung wird jeder Plan vor dem `apply` erneut gegen die Policies geprüft.
  End-to-End-Tests laufen in einem eigenen Job ohne Cloud-Zugang.
- Alle Actions sind per Commit-SHA gepinnt.

## Bekannte Grenzen

- **Abdeckung:** Die Zeilenabdeckung im Check `test` meldet der Projektcode selbst
  (`npm test` schreibt `coverage/coverage-summary.json`). Die Pipeline liest die Schwelle
  aus dem Regelprofil und prüft die Datei, kann aber nicht ausschließen, dass manipulierte
  Tests oder Konfiguration einen zu hohen Wert melden. Das fängt nur das Review im Pull
  Request auf.
- **Ergebnisse der Tests:** Gleiches gilt für Lint, Typprüfung und End-to-End-Tests; sie
  laufen als Projektcode, allerdings ohne Cloud-Zugang und ohne Schreibrecht im Pull Request.
- Die statische Terraform-Prüfung ist bewusst streng (zum Beispiel keine Module). Braucht
  ein Projekt mehr, ändert das Plattform-Team diese Regeln hier.

## Policies lokal prüfen

```text
conftest verify --policy policies/terraform --data profiles
conftest test --policy policies/terraform --data profiles plan.json
```

Jede Ablehnung hat die Form `[regel] adresse: problem. Required change: ...`.

## Version `v1`

Projekte binden `@v1`. `sync-governance` verschiebt den Tag `v1` nach jedem Abgleich
auf den neuen Stand von `main`; dafür wird genau diese Tag-Referenz überschrieben,
nie ein Branch.
