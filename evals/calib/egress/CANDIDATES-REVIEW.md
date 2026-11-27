# CWE-918 candidates — co-selection sheet

Source: `osv` — OSV.dev ecosystem dump https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip (CC-BY-4.0) at `pypi-all.zip`; pinned: sha256 `4072d79a2c099213afb54d2881c9b1684fc3096640df1190865e63caef35009f`, 38344990 bytes, mtime 2026-11-27T20:14:55+00:00; ecosystem PyPI; CWE-918.

Funnel: 27101 records scanned → 27101 PyPI → 276 naming CWE-918 (10 withdrawn upstream, dropped) → 179 with a fix ref (17 PR-only refs resolved to a merge commit, 21 refs still without a single commit) → 247 raw after dedupe → 160 raw with a fix ref (139 with a fix commit).

Rows: 266 advisories naming CWE-918 · 179 with a fix ref · 247 raw after dedupe · 160 raw with a fix ref (139 with a resolved fix commit) · 19 excluded here (duplicates).

Legend: **fix ref** is the single `/commit/<sha>` when the advisory names exactly one, else its PR or first ref (a lone merged GitHub PR is resolved to its merge commit, `fix_commit_source: github-api-pr-merge`), else — (no ref: kept raw; `build.py` excludes it as `no_fix_ref` unless one is supplied at co-selection). **categorical description**, **sub_scenario** and **library** are keyword suggestions from a fixed table (summary first, details as fallback) — confirm or correct them; a blank sub_scenario means no keyword decided. A description of `excluded (duplicate)` marks a later advisory for the same (project, fix) as a kept row. **repo size** is `?` unless known without cloning. **review_underspecified** / **review_test_unfair** (SWE-bench Verified's axes, 0 = fine … 3 = unusable) are yours to fill at co-selection; a task is dropped at >= 2 on either. **Co-selection cap: no project supplies more than 15% of the positives** (see the per-project table). sub_scenario ∈ {redirect, rebinding, off_list, derived_links, oversize, scheme, other}; library ∈ {requests, httpx, urllib, aiohttp, other}.

## Fixable candidates by project (103 projects; cap 15% = at most 24 per project)

| project | fixable candidates | share | over cap? |
|---|---|---|---|
| open-webui/open-webui | 8 | 5% |  |
| WeblateOrg/weblate | 6 | 4% |  |
| langchain-ai/langchain | 6 | 4% |  |
| mlflow/mlflow | 6 | 4% |  |
| MobSF/Mobile-Security-Framework-MobSF | 5 | 3% |  |
| vllm-project/vllm | 5 | 3% |  |
| Netflix/lemur | 4 | 2% |  |
| pyload/pyload | 4 | 2% |  |
| LearningCircuit/local-deep-research | 3 | 2% |  |
| flytohub/flyto-core | 3 | 2% |  |
| gradio-app/gradio | 3 | 2% |  |
| mindsdb/mindsdb | 3 | 2% |  |
| pydantic/pydantic-ai | 3 | 2% |  |
| BerriAI/litellm | 2 | 1% |  |
| Chainlit/chainlit | 2 | 1% |  |
| GeoNode/geonode | 2 | 1% |  |
| HumanSignal/label-studio | 2 | 1% |  |
| apache/airflow | 2 | 1% |  |
| indico/indico | 2 | 1% |  |
| janeczku/calibre-web | 2 | 1% |  |
| koxudaxi/datamodel-code-generator | 2 | 1% |  |
| nltk/nltk | 2 | 1% |  |
| oscal-compass/compliance-trestle | 2 | 1% |  |
| sooperset/mcp-atlassian | 2 | 1% |  |
| Aider-AI/aider | 1 | 1% |  |
| Clinical-Genomics/scout | 1 | 1% |  |
| FoundationAgents/MetaGPT | 1 | 1% |  |
| HKUDS/LightRAG | 1 | 1% |  |
| HKUDS/Vibe-Trading | 1 | 1% |  |
| HKUDS/nanobot | 1 | 1% |  |
| IncludeSecurity/safeurl-python | 1 | 1% |  |
| InternLM/lmdeploy | 1 | 1% |  |
| Kozea/CairoSVG | 1 | 1% |  |
| Kozea/WeasyPrint | 1 | 1% |  |
| Linuxfabrik/lib | 1 | 1% |  |
| Lookyloo/PlaywrightCapture | 1 | 1% |  |
| MISP/misp-modules | 1 | 1% |  |
| ManoManoTech/firefighter-incident | 1 | 1% |  |
| MervinPraison/PraisonAI | 1 | 1% |  |
| PrefectHQ/fastmcp | 1 | 1% |  |
| TAXIIProject/libtaxii | 1 | 1% |  |
| Unstructured-IO/unstructured | 1 | 1% |  |
| aio-libs/aiohttp | 1 | 1% |  |
| apache/streampipes | 1 | 1% |  |
| apache/superset | 1 | 1% |  |
| authlib/authlib | 1 | 1% |  |
| benbusby/whoogle-search | 1 | 1% |  |
| bentoml/BentoML | 1 | 1% |  |
| berriai/litellm | 1 | 1% |  |
| blacklanternsecurity/bbot | 1 | 1% |  |
| bugsink/bugsink | 1 | 1% |  |
| ckan/ckan | 1 | 1% |  |
| codingjoe/django-select2 | 1 | 1% |  |
| cowrie/cowrie | 1 | 1% |  |
| crewAIInc/crewAI | 1 | 1% |  |
| danielgatis/rembg | 1 | 1% |  |
| dgtlmoon/changedetection.io | 1 | 1% |  |
| django/django | 1 | 1% |  |
| dmunozv04/iSponsorBlockTV | 1 | 1% |  |
| docling-project/docling | 1 | 1% |  |
| eidetic-labs/stigmem | 1 | 1% |  |
| ethereum/web3.py | 1 | 1% |  |
| ethyca/fides | 1 | 1% |  |
| explodinggradients/ragas | 1 | 1% |  |
| geolens-io/geolens | 1 | 1% |  |
| geopython/pygeoapi | 1 | 1% |  |
| github/advisory-database | 1 | 1% |  |
| graphite-project/graphite-web | 1 | 1% |  |
| heartexlabs/label-studio | 1 | 1% |  |
| hiyouga/LLaMAFactory | 1 | 1% |  |
| home-assistant/core | 1 | 1% |  |
| inventree/InvenTree | 1 | 1% |  |
| jpadilla/pyjwt | 1 | 1% |  |
| jupyterhub/jupyter-server-proxy | 1 | 1% |  |
| jupyterlab/jupyterlab | 1 | 1% |  |
| keras-team/keras | 1 | 1% |  |
| langflow-ai/langflow | 1 | 1% |  |
| man-group/dtale | 1 | 1% |  |
| matrix-org/sydent | 1 | 1% |  |
| matrix-org/synapse | 1 | 1% |  |
| microsoft/TaskWeaver | 1 | 1% |  |
| microsoft/mcp | 1 | 1% |  |
| mmaitre314/picklescan | 1 | 1% |  |
| modelcontextprotocol/python-sdk | 1 | 1% |  |
| mongodb/mongo-python-driver | 1 | 1% |  |
| mvantellingen/python-zeep | 1 | 1% |  |
| nautobot/nautobot | 1 | 1% |  |
| nicolargo/glances | 1 | 1% |  |
| opencve/opencve | 1 | 1% |  |
| openstack/glance | 1 | 1% |  |
| openstack/swift | 1 | 1% |  |
| pipeboard-co/meta-ads-mcp | 1 | 1% |  |
| py-pdf/fpdf2 | 1 | 1% |  |
| pytorch/serve | 1 | 1% |  |
| ray-project/ray | 1 | 1% |  |
| recurly/recurly-client-python | 1 | 1% |  |
| saleor/requests-hardened | 1 | 1% |  |
| streamlit/streamlit | 1 | 1% |  |
| subzeroid/aiograpi | 1 | 1% |  |
| tensorzero/tensorzero | 1 | 1% |  |
| tony/django-docutils | 1 | 1% |  |
| universal-tool-calling-protocol/python-utcp | 1 | 1% |  |
| unoconv/unoconv | 1 | 1% |  |

## Candidates by disclosure year

| year | advisories | fixable raw | share of fixable |
|---|---|---|---|
| 2019 | 3 | 3 | 2% |
| 2020 | 1 | 1 | 1% |
| 2021 | 7 | 3 | 2% |
| 2022 | 7 | 6 | 4% |
| 2023 | 17 | 13 | 8% |
| 2024 | 18 | 15 | 9% |
| 2025 | 21 | 13 | 8% |
| 2026 | 192 | 106 | 66% |

## Candidates

| advisory | project | disclosure date | fix ref | categorical description | suggested sub_scenario | suggested library | repo size (.py files) | review_underspecified (0–3) | review_test_unfair (0–3) |
|---|---|---|---|---|---|---|---|---|---|
| GHSA-38rv-5jqc-m2cv | recurly/recurly-client-python | 2019-01-04 | https://github.com/recurly/recurly-client-python/commit/049c74699ce93cf126feff06d632ea63fba36742 | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-27p5-7cw6-m45h | unoconv/unoconv | 2019-10-24 | https://github.com/unoconv/unoconv/pull/510 | URL scheme not restricted | scheme | — | ? |   |   |
| GHSA-vfj6-275q-4pvm | graphite-project/graphite-web | 2019-10-25 | https://github.com/graphite-project/graphite-web/commit/71726a0e41a5263f49b973a7b856505a5b931c1f | image URL from user input fetched without host check | off_list | — | ? |   |   |
| GHSA-6r3p-fcvm-xh7c | apache/airflow | 2020-12-17 | https://github.com/apache/airflow/commit/b606b871226d649913a37fd074eeae5d86ebc3a1 | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-mpvw-25mg-59vx | hg-public/reportlab | 2021-03-29 | — | links derived from fetched content fetched without host check | derived_links | — | ? |   |   |
| GHSA-x7wf-5mjc-6x76 | — | 2021-04-07 | — | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-9jhm-8m8c-c3f4 | matrix-org/sydent | 2021-04-19 | https://github.com/matrix-org/sydent/commit/0f00412017f25619bc36c264b29ea96808bf310a | internal address block-list incomplete | off_list | — | ? |   |   |
| GHSA-836c-xg97-8p4h | TAXIIProject/libtaxii | 2021-04-30 | https://github.com/TAXIIProject/libtaxii/commit/23c6f7b69d99e965c8d53dc4710ae64da3fb4842 | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-p99v-5w3c-jqq9 | django/django | 2021-06-10 | https://github.com/django/django/commit/203d4ab9ebcd72fc4d6eb7398e66ed9e474e118e | URL scheme not restricted | scheme | — | ? |   |   |
| GHSA-4mg4-wvmx-5332 | plone/Plone | 2021-06-15 | — | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-gc9g-67cq-p7v4 | plone/Plone | 2021-06-15 | — | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-gcv9-6737-pjqw | jupyterhub/jupyter-server-proxy | 2022-01-27 | https://github.com/jupyterhub/jupyter-server-proxy/commit/fd31930bacd12188c448c886e0783529436b99eb | proxy setting from user input routes outbound traffic | other | — | ? |   |   |
| GHSA-4w8p-x6g8-fv64 | janeczku/calibre-web | 2022-02-01 | https://github.com/janeczku/calibre-web/commit/35f6f4c727c887f8f3607fe3233dbc1980d15020 | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-2647-c639-qv2j | janeczku/calibre-web | 2022-03-08 | https://github.com/janeczku/calibre-web/commit/965352c8d96c9eae7a6867ff76b0db137d04b0b8 | internal address block-list incomplete | off_list | — | ? |   |   |
| GHSA-h65g-jfqg-2w6m | janeczku/calibre-web | 2022-03-08 | https://github.com/janeczku/calibre-web/commit/965352c8d96c9eae7a6867ff76b0db137d04b0b8 | excluded (duplicate) | redirect | — | ? |   |   |
| GHSA-g53g-q539-93cv | Clinical-Genomics/scout | 2022-05-06 | https://github.com/clinical-genomics/scout/commit/b0ef15f4737d0c801154c1991b52ff5cab4f5c83 | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-j6mr-cm6x-h6jg | openstack/glance | 2022-05-17 | https://github.com/openstack/glance/commit/b1ac90f7914d91b25144cc4063fa994fb5019ee3 | image URL from user input fetched without host check | off_list | — | ? |   |   |
| GHSA-pc6f-259w-w3j6 | heartexlabs/label-studio | 2022-10-04 | https://github.com/heartexlabs/label-studio/commit/501142cb815ac964b0c600c491885b67386870c2 | download URL from user input fetched without host check | off_list | — | ? |   |   |
| GHSA-jgh8-vchw-q3g7 | IncludeSecurity/safeurl-python | 2023-01-27 | https://github.com/IncludeSecurity/safeurl-python/commit/42dd0c8e5fc84e17e1d3578d18aaea169eece474 | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-47p5-p3jw-w78w | plone/Plone | 2023-02-17 | — | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-rwmf-w63j-p7gv | Kozea/CairoSVG | 2023-03-20 | https://github.com/Kozea/CairoSVG/commit/12d31c653c0254fa9d9853f66b04ea46e7397255 | links derived from fetched content fetched without host check | derived_links | — | ? |   |   |
| GHSA-98px-6486-j7qc | matrix-org/synapse | 2023-06-06 | https://github.com/matrix-org/synapse/pull/15601 | links derived from fetched content fetched without host check | derived_links | — | ? |   |   |
| GHSA-fxjg-28fm-pfxh | apache/superset | 2023-07-06 | — | download URL from user input fetched without host check | off_list | — | ? |   |   |
| GHSA-x2mh-8fmc-rqgh | apache/airflow | 2023-08-23 | https://github.com/apache/airflow/commit/e4c3ecf8ceaefa17525b495e4bcb5b2f41309603 | response size or outbound volume not bounded | oversize | — | ? |   |   |
| GHSA-4fg9-5w46-xmrj | apache/superset | 2023-09-06 | — | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-9832-mgg4-3gr6 | apache/superset | 2023-09-06 | https://github.com/apache/superset/pull/24185 | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-pxg5-h34r-7q8p | GeoNode/geonode | 2023-09-20 | https://github.com/GeoNode/geonode/commit/79ac6e70419c2e0261548bed91c159b54ff35b8d | internal address block-list incomplete | off_list | — | ? |   |   |
| GHSA-8fxr-qfr9-p34w | pytorch/serve | 2023-10-02 | https://github.com/pytorch/serve/pull/2534 | server base URL from configuration fetched unchecked | off_list | — | ? |   |   |
| GHSA-655w-fm8m-m478 | langchain-ai/langchain | 2023-10-19 | https://github.com/langchain-ai/langchain/commit/9ecb7240a480720ec9d739b3877a52f76098a2b8 | links derived from fetched content fetched without host check | derived_links | — | ? |   |   |
| GHSA-6h8p-4hx9-w66c | langchain-ai/langchain | 2023-10-21 | https://github.com/langchain-ai/langchain/pull/12747 | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-jq3w-9mgf-43m4 | ethyca/fides | 2023-10-24 | https://github.com/ethyca/fides/commit/cd344d016b1441662a61d0759e7913e8228ed1ee | download URL from user input fetched without host check | off_list | — | ? |   |   |
| GHSA-6wgj-66m2-xxp2 | ray-project/ray | 2023-11-28 | https://github.com/ray-project/ray/commit/978947083b1e192dba61ef653c863b11d56b0936 | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-34mr-6q8x-g9r6 | mindsdb/mindsdb | 2023-12-12 | https://github.com/mindsdb/mindsdb/commit/8d13c9c28ebcf3b36509eb679378004d4648d8fe | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-j8w6-2r9h-cxhj | mindsdb/mindsdb | 2023-12-15 | — | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-59v3-898r-qwhj | mlflow/mlflow | 2023-12-20 | https://github.com/mlflow/mlflow/commit/8174250f83352a04c2d42079f414759060458555 | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-7hfx-h3j3-rwq4 | man-group/dtale | 2024-01-05 | https://github.com/man-group/dtale/commit/954f6be1a06ff8629ead2c85c6e3f8e2196b3df2 | download URL from user input fetched without host check | off_list | — | ? |   |   |
| GHSA-p59w-9gqw-wj8r | HumanSignal/label-studio | 2024-01-31 | https://github.com/HumanSignal/label-studio/commit/55dd6af4716b92f2bb213fe461d1ffbc380c6a64 | download URL from user input fetched without host check | off_list | requests | ? |   |   |
| GHSA-h9j7-5xvc-qhg5 | langchain-ai/langchain | 2024-02-26 | https://github.com/langchain-ai/langchain/commit/bf0b3cc0b5ade1fb95a5b1b6fa260e99064c2e22 | links derived from fetched content fetched without host check | derived_links | — | ? |   |   |
| GHSA-3q6g-qmpx-rqw4 | benbusby/whoogle-search | 2024-03-14 | https://github.com/benbusby/whoogle-search/commit/3a2e0b262e4a076a20416b45e6b6f23fd265aeda | links derived from fetched content fetched without host check | derived_links | — | ? |   |   |
| GHSA-q97g-c29h-x2p7 | benbusby/whoogle-search | 2024-03-14 | https://github.com/benbusby/whoogle-search/commit/3a2e0b262e4a076a20416b45e6b6f23fd265aeda | excluded (duplicate) | derived_links | — | ? |   |   |
| GHSA-wfgj-wrgh-h3r3 | MobSF/Mobile-Security-Framework-MobSF | 2024-03-22 | https://github.com/MobSF/Mobile-Security-Framework-MobSF/commit/5a8eeee73c5f504a6c3abdf2a139a13804efdb77 | URL scheme not restricted | scheme | — | ? |   |   |
| GHSA-r364-m2j9-mf4h | gradio-app/gradio | 2024-03-27 | https://github.com/gradio-app/gradio/commit/49d9c48537aa706bf72628e3640389470138bdc6 | proxy setting from user input routes outbound traffic | other | — | ? |   |   |
| GHSA-wpff-wm84-x5cx | MobSF/Mobile-Security-Framework-MobSF | 2024-04-04 | https://github.com/MobSF/Mobile-Security-Framework-MobSF/commit/43bb71d115d78c03faa82d75445dd908e9b32716 | download URL from user input fetched without host check | off_list | — | ? |   |   |
| GHSA-973g-55hp-3frw | gradio-app/gradio | 2024-06-06 | https://github.com/gradio-app/gradio/pull/8301 | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-q25c-c977-4cmh | langchain-ai/langchain | 2024-06-06 | https://github.com/langchain-ai/langchain/commit/604dfe2d99246b0c09f047c604f0c63eafba31e7 | proxy setting from user input routes outbound traffic | other | — | ? |   |   |
| GHSA-9gr7-gh74-qg9x | apache/streampipes | 2024-07-17 | https://github.com/apache/streampipes/commit/cd5a7b46e3383573f0f2b51da4b7306d4936aa3f | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-g9ph-j5vj-f8wm | ckan/ckan | 2024-08-21 | https://github.com/ckan/ckan/commit/382beaec98cb331f2a030459ef043c50eaf5ad53 | proxy setting from user input routes outbound traffic | other | — | ? |   |   |
| GHSA-4jcv-vp96-94xr | mindsdb/mindsdb | 2024-09-05 | https://github.com/mindsdb/mindsdb/commit/5f7496481bd3db1d06a2d2e62c0dce960a1fe12b | host re-resolved after validation (DNS rebinding) | rebinding | requests | ? |   |   |
| GHSA-g26j-5385-hhw3 | berriai/litellm | 2024-09-13 | https://github.com/berriai/litellm/commit/ba1912afd1b19e38d3704bb156adf887f91ae1e0 | server base URL from configuration fetched unchecked | off_list | — | ? |   |   |
| GHSA-vx3h-qwqw-r2wq | inventree/InvenTree | 2024-10-02 | https://github.com/inventree/InvenTree/commit/5759b60a48e7e178fb417a900ed543f29dc5dc86 | image URL from user input fetched without host check | off_list | — | ? |   |   |
| GHSA-576c-3j53-r9jj | gradio-app/gradio | 2024-10-10 | — | download URL from user input fetched without host check | off_list | — | ? |   |   |
| GHSA-3gf9-wv65-gwh9 | gradio-app/gradio | 2024-11-05 | — | download URL from user input fetched without host check | off_list | — | ? |   |   |
| GHSA-rmxg-6qqf-x8mr | GeoNode/geonode | 2024-11-21 | https://github.com/GeoNode/geonode/commit/a9eebae80cb362009660a1fd49e105e7cdb499b9 | proxy setting from user input routes outbound traffic | other | — | ? |   |   |
| GHSA-m238-fmcw-wh58 | HumanSignal/label-studio | 2025-02-14 | https://github.com/HumanSignal/label-studio/commit/06a2b29c1208e1878ccae66e6b84c8b24598fa79 | server base URL from configuration fetched unchecked | off_list | — | ? |   |   |
| GHSA-r5gx-c49x-h878 | danielgatis/rembg | 2025-03-11 | — | image URL from user input fetched without host check | off_list | — | ? |   |   |
| GHSA-38mg-wm59-g64x | ComposioHQ/composio | 2025-03-20 | — | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-g44m-hpf4-vmrp | lm-sys/FastChat | 2025-03-20 | — | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-h254-g997-685c | lm-sys/FastChat | 2025-03-20 | — | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-qvg9-vp87-h3hr | ComposioHQ/composio | 2025-03-20 | — | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-fcfq-m8p6-gw56 | MobSF/Mobile-Security-Framework-MobSF | 2025-03-31 | https://github.com/MobSF/Mobile-Security-Framework-MobSF/commit/4b8bab5a9858c69fe13be4631b82d82186e0d3bd | host re-resolved after validation (DNS rebinding) | rebinding | urllib | ? |   |   |
| GHSA-qp8j-p87f-c8cc | lnbits/lnbits | 2025-04-07 | — | webhook or callback URL fetched without host check | off_list | httpx | ? |   |   |
| GHSA-445m-27cf-gr3x | unclecode/crawl4ai | 2025-04-18 | — | links derived from fetched content fetched without host check | derived_links | — | ? |   |   |
| GHSA-wjrh-hj83-3wh7 | codingjoe/django-select2 | 2025-05-27 | https://github.com/codingjoe/django-select2/commit/e5f41e6edba004d35f94915ff5e2559f44853412 | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-h5gc-rm8j-5gpr | langchain-ai/langchain | 2025-06-23 | https://github.com/langchain-ai/langchain/commit/e188d4ecb085d4561a0be3c583d26aa9c2c3283f | server base URL from configuration fetched unchecked | off_list | — | ? |   |   |
| GHSA-wxj7-3fx5-pp9m | mlflow/mlflow | 2025-06-23 | https://github.com/mlflow/mlflow/pull/15970 | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-m435-9v6r-v5f6 | MobSF/Mobile-Security-Framework-MobSF | 2025-06-27 | https://github.com/MobSF/Mobile-Security-Framework-MobSF/commit/f22c584aa7d43527970c9da61eb678953cfc0a8e | redirect to internal address not re-validated | redirect | requests | ? |   |   |
| GHSA-mrmq-3q62-6cc8 | bentoml/BentoML | 2025-07-29 | https://github.com/bentoml/BentoML/commit/534c3584621da4ab954bdc3d814cc66b95ae5fb8 | download URL from user input fetched without host check | off_list | other | ? |   |   |
| GHSA-3f6c-7fw2-ppm4 | vllm-project/vllm | 2025-10-07 | https://github.com/vllm-project/vllm/commit/9d9a2b77f19f68262d5e469c4e82c0f6365ad72d | response size or outbound volume not bounded | oversize | — | ? |   |   |
| GHSA-527m-2xhr-j27g | hiyouga/LLaMAFactory | 2025-10-07 | https://github.com/hiyouga/LLaMAFactory/commit/95b7188090a1018935c9dc072bfc97f24f1c96e9 | URL scheme not restricted | scheme | requests | ? |   |   |
| GHSA-mq84-hjqx-cwf2 | keras-team/keras | 2025-10-29 | https://github.com/keras-team/keras/commit/61ac8c1e51862c471dee7b49029c356f55531487 | URL scheme not restricted | scheme | — | ? |   |   |
| GHSA-c6xv-rcvw-v685 | open-webui/open-webui | 2025-12-04 | https://github.com/open-webui/open-webui/commit/02238d3113e966c353fce18f1b65117380896774 | download URL from user input fetched without host check | off_list | other | ? |   |   |
| GHSA-5993-7p27-66g5 | langflow-ai/langflow | 2025-12-19 | — | internal address block-list incomplete | off_list | httpx | ? |   |   |
| GHSA-83jg-m2pm-4jxj | cowrie/cowrie | 2025-12-20 | https://github.com/cowrie/cowrie/pull/2800 | response size or outbound volume not bounded | oversize | other | ? |   |   |
| GHSA-9c54-gxh7-ppjc | LearningCircuit/local-deep-research | 2025-12-23 | https://github.com/LearningCircuit/local-deep-research/commit/b79089ff30c5d9ae77e6b903c408e1c26ad5c055 | download URL from user input fetched without host check | off_list | requests | ? |   |   |
| GHSA-9726-w42j-3qjr | mmaitre314/picklescan | 2026-01-08 | https://github.com/mmaitre314/picklescan/commit/a01c58d5dd7960db557b849817c0ab83ab111ef1 | URL scheme not restricted | scheme | urllib | ? |   |   |
| GHSA-2g59-m95p-pgfq | Chainlit/chainlit | 2026-01-20 | https://github.com/Chainlit/chainlit/commit/ffc3cce648b343b933e10e85ee5805c7e02ab3bf | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-983w-rhvv-gwmv | Kozea/WeasyPrint | 2026-01-20 | https://github.com/Kozea/WeasyPrint/commit/b6a14f0f3f4ce9c0c75c1a2d73cb1c5d43f0e565 | redirect to internal address not re-validated | redirect | urllib | ? |   |   |
| GHSA-gpx9-96j6-pp87 | microsoft/TaskWeaver | 2026-01-28 | https://github.com/microsoft/TaskWeaver/commit/d635599f03488c857e1919fcc8303cc5a09e9a0a | server base URL from configuration fetched unchecked | off_list | — | ? |   |   |
| GHSA-qh4c-xf7m-gxfc | vllm-project/vllm | 2026-01-28 | https://github.com/vllm-project/vllm/commit/f46d576c54fb8aeec5fc70560e850bed38ef17d7 | response size or outbound volume not bounded | oversize | urllib | ? |   |   |
| GHSA-2jrp-274c-jhv3 | pydantic/pydantic-ai | 2026-02-06 | https://github.com/pydantic/pydantic-ai/commit/d398bc9d39aecca6530fa7486a410d5cce936301 | download URL from user input fetched without host check | off_list | urllib | ? |   |   |
| GHSA-6fgp-m6q4-j3q5 | pydantic/mcp-run-python | 2026-02-09 | — | server base URL from configuration fetched unchecked | off_list | — | ? |   |   |
| GHSA-v34v-rq6j-cj6p | langchain-ai/langsmith-sdk | 2026-02-09 | — | URL taken from a request header fetched unchecked | off_list | — | ? |   |   |
| GHSA-2g6r-c272-w58r | langchain-ai/langchain | 2026-02-11 | https://github.com/langchain-ai/langchain/commit/2b4b1dc29a833d4053deba4c2b77a3848c834565 | response size or outbound volume not bounded | oversize | httpx | ? |   |   |
| GHSA-6xw9-2p64-7622 | mindsdb/mindsdb | 2026-02-16 | https://github.com/themavik/mindsdb/commit/74d6f0fd4b630218519a700fbee1c05c7fd4b1ed | download URL from user input fetched without host check | off_list | — | ? |   |   |
| GHSA-f47c-3c5w-v7p4 | indico/indico | 2026-02-17 | https://github.com/indico/indico/commit/70d341826116fac5868719a6133f2c26d9345137 | proxy setting from user input routes outbound traffic | other | — | ? |   |   |
| GHSA-jxgv-6j54-wwc7 | huggingface/smolagents | 2026-02-18 | — | URL from user input fetched without host check | — | requests | ? |   |   |
| GHSA-3c45-4pj5-ch7m | dgtlmoon/changedetection.io | 2026-02-25 | https://github.com/dgtlmoon/changedetection.io/commit/fe7aa38c651d73fe5f41ce09855fa8f97193747b | internal address allow-list misses an address encoding | off_list | other | ? |   |   |
| GHSA-jmh7-g254-2cq9 | gradio-app/gradio | 2026-03-01 | https://github.com/gradio-app/gradio/commit/fc7c01ea1e581ef70be98fddf003b0c91315c7cc | proxy setting from user input routes outbound traffic | other | httpx | ? |   |   |
| GHSA-fpx8-73gf-7x73 | makeplane/plane | 2026-03-05 | — | internal address block-list incomplete | off_list | — | ? |   |   |
| GHSA-v2xr-wvrv-p969 | explodinggradients/ragas | 2026-03-05 | https://github.com/vibrantlabsai/ragas/commit/b28433709cbedbb531db79dadcfbdbd3aa6adcb0 | URL scheme not restricted | scheme | — | ? |   |   |
| GHSA-v359-jj2v-j536 | vllm-project/vllm | 2026-03-09 | https://github.com/vllm-project/vllm/commit/6f3b2047abd4a748e3db4a68543f8221358002c0 | internal address block-list incomplete | off_list | — | ? |   |   |
| GHSA-7r34-79r5-rcc9 | sooperset/mcp-atlassian | 2026-03-10 | https://github.com/sooperset/mcp-atlassian/commit/5cd697dfce9116ef330b8dc7a91291640e0528d9 | URL taken from a request header fetched unchecked | off_list | httpx | ? |   |   |
| GHSA-hhfx-wfvq-7g9c | microsoft/mcp | 2026-03-10 | https://github.com/microsoft/mcp/commit/804ff60293206c4d8e832f772097238561bf2c34 | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-fmfg-9g7c-3vq7 | homeassistant-ai/ha-mcp | 2026-03-12 | — | URL scheme not restricted | scheme | — | ? |   |   |
| GHSA-7p48-42j8-8846 | streamlit/streamlit | 2026-03-25 | https://github.com/streamlit/streamlit/commit/23692ca70b2f2ac720c72d1feb4f190c9d6eed76 | UNC path accepted as a URL (credential leak) | scheme | — | ? |   |   |
| GHSA-m74m-f7cr-432x | pyload/pyload | 2026-03-27 | https://github.com/pyload/pyload/commit/b76b6d4ee5e32d2118d26afdee1d0a9e57d4bfe8 | download URL from user input fetched without host check | off_list | — | ? |   |   |
| GHSA-mc26-q38v-83gv | openstack/glance | 2026-03-31 | — | redirect to internal address not re-validated | redirect | — | ? |   |   |
| GHSA-vv7q-7jx5-f767 | PrefectHQ/fastmcp | 2026-03-31 | https://github.com/PrefectHQ/fastmcp/commit/40bdfb6b1de0ce30609ee9ba5bb95ecd04a9fb71 | server base URL from configuration fetched unchecked | off_list | urllib | ? |   |   |
| GHSA-44c2-3rw4-5gvh | MervinPraison/PraisonAI | 2026-04-01 | — | download URL from user input fetched without host check | off_list | httpx | ? |   |   |
| GHSA-p998-jp59-783m | aio-libs/aiohttp | 2026-04-01 | https://github.com/aio-libs/aiohttp/commit/0ae2aa076c84573df83fc1fdc39eec0f5862fe3d | UNC path accepted as a URL (credential leak) | scheme | aiohttp | ? |   |   |
| GHSA-x6m9-gxvr-7jpv | MervinPraison/PraisonAI | 2026-04-01 | — | server base URL from configuration fetched unchecked | off_list | httpx | ? |   |   |
| GHSA-pf3h-qjgv-vcpr | vllm-project/vllm | 2026-04-03 | https://github.com/vllm-project/vllm/commit/57861ae48d3493fa48b4d7d830b7ec9f995783e7 | download URL from user input fetched without host check | off_list | aiohttp | ? |   |   |
| GHSA-qw2m-4pqf-rmpp | lexiforest/curl_cffi | 2026-04-03 | — | redirect to internal address not re-validated | redirect | other | ? |   |   |
| GHSA-2wvg-62qm-gj33 | pyload/pyload | 2026-04-04 | https://github.com/pyload/pyload/commit/4032e57d61d8f864e39f4dcfdb567527a50a9e1f | download URL from user input fetched without host check | off_list | urllib | ? |   |   |
| GHSA-5hr4-253g-cpx2 | ethereum/web3.py | 2026-04-04 | https://github.com/ethereum/web3.py/commit/b1c57bb0a124359c9902daaefab4d8af7c3c4c1e | links derived from fetched content fetched without host check | derived_links | aiohttp | ? |   |   |
| GHSA-7gvf-3w72-p2pg | pyload/pyload | 2026-04-04 | https://github.com/pyload/pyload/commit/33c55da084320430edfd941b60e3da0eb1be9443 | redirect to internal address not re-validated | redirect | urllib | ? |   |   |
| GHSA-55v6-g8pm-pw4c | danielgatis/rembg | 2026-04-10 | https://github.com/danielgatis/rembg/commit/07ad0d493057bddf821dcc3e2410eb7e065257c0 | server base URL from configuration fetched unchecked | off_list | aiohttp | ? |   |   |
| GHSA-8f4v-xfm9-3244 | MervinPraison/PraisonAI | 2026-04-10 | — | URL scheme not restricted | scheme | urllib | ? |   |   |
| GHSA-8frj-8q3m-xhgm | MervinPraison/PraisonAI | 2026-04-10 | — | webhook or callback URL fetched without host check | off_list | httpx | ? |   |   |
| GHSA-qq9r-63f6-v542 | MervinPraison/PraisonAI | 2026-04-10 | — | redirect to internal address not re-validated | redirect | httpx | ? |   |   |
| GHSA-r5v8-c28h-f8r8 | FoundationAgents/MetaGPT | 2026-04-12 | https://github.com/FoundationAgents/MetaGPT/pull/1941 | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-5fhx-9jwj-867m | WeblateOrg/weblate | 2026-04-16 | https://github.com/WeblateOrg/weblate/commit/8be80625a864c8db5854503872a65e8a0b7399a6 | redirect to internal address not re-validated | redirect | — | ? |   |   |
| GHSA-f8hv-g549-hwg2 | WeblateOrg/weblate | 2026-04-16 | https://github.com/WeblateOrg/weblate/pull/18815 | webhook or callback URL fetched without host check | off_list | — | ? |   |   |
| GHSA-fv5p-p927-qmxr | langchain-ai/langchain | 2026-04-16 | — | redirect to internal address not re-validated | redirect | requests | ? |   |   |
| GHSA-r7w7-9xr2-qq2r | langchain-ai/langchain | 2026-04-16 | — | host re-resolved after validation (DNS rebinding) | rebinding | httpx | ? |   |   |
| GHSA-xrwr-fcw6-fmq8 | WeblateOrg/weblate | 2026-04-16 | https://github.com/WeblateOrg/weblate/commit/e619e9090202e4886b844c110d39308e7e882c0e | server base URL from configuration fetched unchecked | off_list | — | ? |   |   |
| GHSA-659x-hm75-hpv7 | agentscope-ai/agentscope | 2026-04-20 | — | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-8ggf-r3vm-p3jc | agentscope-ai/agentscope | 2026-04-20 | — | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-95ww-475f-pr4f | vibrantlabsai/ragas | 2026-04-20 | — | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-crx8-wpv6-jrj2 | agentscope-ai/agentscope | 2026-04-20 | — | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-6w67-hwm5-92mq | InternLM/lmdeploy | 2026-04-21 | https://github.com/InternLM/lmdeploy/commit/71d64a339edb901e9005358e0633fbbab367d626 | image URL from user input fetched without host check | off_list | — | ? |   |   |
| GHSA-g5pq-48mj-jvw8 | nicolargo/glances | 2026-04-21 | https://github.com/nicolargo/glances/commit/d6808be66728956477cc4b544bab1acd71ac65fb | URL scheme not restricted | scheme | urllib | ? |   |   |
| GHSA-h7xc-4mv8-59fj | dmitryglhf/url-download-mcp | 2026-04-27 | — | download URL from user input fetched without host check | off_list | — | ? |   |   |
| GHSA-vmh7-9c7h-2pgg | dh1011/auto-favicon-mcp | 2026-04-27 | — | image URL from user input fetched without host check | off_list | — | ? |   |   |
| GHSA-jgvc-94c8-3chc | geopython/pygeoapi | 2026-04-29 | https://github.com/geopython/pygeoapi/commit/3a63f5b0cc6275e3ae0edb47726b13a43cdd90ef | server base URL from configuration fetched unchecked | off_list | — | ? |   |   |
| GHSA-cwcx-382v-8m9g | WeblateOrg/weblate | 2026-04-30 | https://github.com/WeblateOrg/weblate/pull/19061 | download URL from user input fetched without host check | off_list | — | ? |   |   |
| GHSA-pg67-9wjv-mr85 | pyload/pyload | 2026-05-04 | — | redirect to internal address not re-validated | redirect | other | ? |   |   |
| GHSA-64cv-vxpr-j6vc | openedx/edx-enterprise | 2026-05-05 | — | links derived from fetched content fetched without host check | derived_links | requests | ? |   |   |
| GHSA-fqvv-jvhr-g5jc | ManoManoTech/firefighter-incident | 2026-05-05 | https://github.com/ManoManoTech/firefighter-incident/commit/2586679e6f32c12d223668b73e98f4c4de7b771f | internal address allow-list misses an address encoding | off_list | httpx | ? |   |   |
| GHSA-vh75-fwv3-pqrh | saleor/requests-hardened | 2026-05-05 | https://github.com/saleor/requests-hardened/commit/a266b3958bb142bca515b3c230fdea19fbda327c | internal address allow-list misses an address encoding | off_list | — | ? |   |   |
| GHSA-687h-xw6f-q2qw | Lookyloo/PlaywrightCapture | 2026-05-06 | https://github.com/Lookyloo/PlaywrightCapture/commit/49e289eba756e4fbac1322c33cfd111411562405 | links derived from fetched content fetched without host check | derived_links | other | ? |   |   |
| GHSA-fhq3-2gf3-8f3j | MISP/misp-modules | 2026-05-06 | https://github.com/MISP/misp-modules/commit/52cda9caa003cafe87e14ae3721db5e16f6f111a | download URL from user input fetched without host check | off_list | — | ? |   |   |
| GHSA-q9pw-vmhh-384g | MervinPraison/PraisonAI | 2026-05-06 | — | internal address block-list incomplete | off_list | requests | ? |   |   |
| GHSA-39j6-4867-gg4w | universal-tool-calling-protocol/python-utcp | 2026-05-07 | — | server base URL from configuration fetched unchecked | off_list | — | ? |   |   |
| GHSA-fqph-j6v6-jvgx | docling-project/docling-graph | 2026-05-07 | — | redirect to internal address not re-validated | redirect | requests | ? |   |   |
| GHSA-fp53-qcf8-2xx2 | bugsink/bugsink | 2026-05-08 | https://github.com/bugsink/bugsink/commit/940d2df635e06803ef658666d734306942db5cc7 | internal address block-list incomplete | off_list | urllib | ? |   |   |
| GHSA-587r-mc96-6f2p | DataDog/guarddog | 2026-05-11 | — | URL taken from a request header fetched unchecked | off_list | requests | ? |   |   |
| GHSA-65h7-c7c4-mghx | mlflow/mlflow | 2026-05-11 | https://github.com/mlflow/mlflow/commit/64aa0ab7207f9c649b59ba1a5f40d82196817389 | URL scheme not restricted | scheme | — | ? |   |   |
| GHSA-fj2m-qvh9-jq4q | LearningCircuit/local-deep-research | 2026-05-11 | https://github.com/LearningCircuit/local-deep-research/pull/3082 | response size or outbound volume not bounded | oversize | — | ? |   |   |
| GHSA-c35q-vxrp-ph26 | nautobot/nautobot | 2026-05-13 | https://github.com/nautobot/nautobot/commit/16aa4aa9796ab7a31c4d615ec945e1f16d8c77c4 | webhook or callback URL fetched without host check | off_list | — | ? |   |   |
| GHSA-24c9-2m8q-qhmh | open-webui/open-webui | 2026-05-14 | — | image URL from user input fetched without host check | off_list | urllib | ? |   |   |
| GHSA-4v7r-f4w8-8972 | open-webui/open-webui | 2026-05-14 | — | redirect to internal address not re-validated | redirect | requests | ? |   |   |
| GHSA-8w7q-q5jp-jvgx | open-webui/open-webui | 2026-05-14 | — | host re-resolved after validation (DNS rebinding) | rebinding | urllib | ? |   |   |
| GHSA-f776-fp4w-266c | open-webui/open-webui | 2026-05-14 | https://github.com/open-webui/open-webui/commit/167c8bf00d165af523acfc3b870749f6be6d3e57 | webhook or callback URL fetched without host check | off_list | — | ? |   |   |
| GHSA-rh5x-h6pp-cjj6 | open-webui/open-webui | 2026-05-14 | — | redirect to internal address not re-validated | redirect | aiohttp | ? |   |   |
| GHSA-3r75-xc34-5f44 | apify/crawlee-python | 2026-05-21 | — | links derived from fetched content fetched without host check | derived_links | other | ? |   |   |
| GHSA-8rp3-xc6w-5qp5 | pyload/pyload | 2026-05-21 | — | redirect to internal address not re-validated | redirect | other | ? |   |   |
| GHSA-cqp8-fcvh-x7r3 | pydantic/pydantic-ai | 2026-05-21 | — | internal address allow-list misses an address encoding | off_list | — | ? |   |   |
| GHSA-xq32-9g7q-7297 | flaskbb/flaskbb | 2026-05-21 | — | image URL from user input fetched without host check | off_list | requests | ? |   |   |
| GHSA-ggxf-37hm-9wqf | subzeroid/instagrapi | 2026-05-23 | — | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-jh37-x3fv-4x72 | subzeroid/aiograpi | 2026-05-23 | https://github.com/subzeroid/aiograpi/commit/9c24151916beca622e588bfb3167c98711ff744f | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-hfpv-mc5v-p9mm | WeblateOrg/weblate | 2026-05-26 | https://github.com/WeblateOrg/weblate/pull/17102 | URL scheme not restricted | scheme | — | ? |   |   |
| GHSA-g23j-2vwm-5c25 | LearningCircuit/local-deep-research | 2026-05-28 | https://github.com/LearningCircuit/local-deep-research/pull/3873 | internal address block-list incomplete | off_list | — | ? |   |   |
| GHSA-w76h-q7c6-jpjp | oscal-compass/compliance-trestle | 2026-05-28 | https://github.com/oscal-compass/compliance-trestle/commit/53de5e75332888ea54f5da41d4c7859bb1d608e1 | download URL from user input fetched without host check | off_list | requests | ? |   |   |
| GHSA-5c6w-wwfq-7qqm | MervinPraison/PraisonAI | 2026-05-29 | — | internal address allow-list misses an address encoding | off_list | requests | ? |   |   |
| GHSA-hchg-qm84-cj9p | Aider-AI/aider | 2026-05-31 | https://github.com/Aider-AI/aider/pull/5137 | URL from user input fetched without host check | — | requests | ? |   |   |
| GHSA-434r-7c99-hwf3 | HKUDS/nanobot | 2026-06-01 | https://github.com/HKUDS/nanobot/commit/545294c62c0947da40eb5b65288aaf02b5fdf632 | redirect to internal address not re-validated | redirect | httpx | ? |   |   |
| GHSA-jmmv-h3mp-59v8 | docling-project/docling-core | 2026-06-03 | — | download URL from user input fetched without host check | off_list | — | ? |   |   |
| GHSA-pj2v-ggqh-cmq2 | docling-project/docling | 2026-06-03 | — | links derived from fetched content fetched without host check | derived_links | other | ? |   |   |
| GHSA-hw9r-6m78-w6h3 | GeoNode/geonode | 2026-06-08 | — | server base URL from configuration fetched unchecked | off_list | — | ? |   |   |
| GHSA-4mj9-pf4r-cqrc | learningequality/kolibri | 2026-06-11 | — | redirect to internal address not re-validated | redirect | other | ? |   |   |
| GHSA-993g-76c3-p5m4 | github/advisory-database | 2026-06-15 | https://github.com/github/advisory-database/pull/8521 | URL scheme not restricted | scheme | urllib | ? |   |   |
| GHSA-wqp7-x3pw-xc5r | Kludex/starlette | 2026-06-15 | — | UNC path accepted as a URL (credential leak) | scheme | — | ? |   |   |
| GHSA-365w-hqf6-vxfg | unclecode/crawl4ai | 2026-06-16 | — | links derived from fetched content fetched without host check | derived_links | — | ? |   |   |
| GHSA-4qqr-vv2q-cmr5 | unclecode/crawl4ai | 2026-06-16 | — | internal address allow-list misses an address encoding | off_list | — | ? |   |   |
| GHSA-6qhc-x826-342c | unclecode/crawl4ai | 2026-06-16 | — | proxy setting from user input routes outbound traffic | other | other | ? |   |   |
| GHSA-f989-c77f-r2cq | unclecode/crawl4ai | 2026-06-16 | — | links derived from fetched content fetched without host check | derived_links | — | ? |   |   |
| GHSA-226f-f24g-524w | open-webui/open-webui | 2026-06-17 | — | redirect to internal address not re-validated | redirect | aiohttp | ? |   |   |
| GHSA-jrfp-m64g-pcwv | open-webui/open-webui | 2026-06-17 | — | redirect to internal address not re-validated | redirect | other | ? |   |   |
| GHSA-r2wg-2mcr-66rv | open-webui/open-webui | 2026-06-17 | — | proxy setting from user input routes outbound traffic | other | — | ? |   |   |
| GHSA-3mp7-vp6j-2mxx | blacklanternsecurity/bbot | 2026-06-18 | https://github.com/blacklanternsecurity/bbot/commit/c2f4bc0f4 | links derived from fetched content fetched without host check | derived_links | — | ? |   |   |
| GHSA-4pcv-mg8v-vrgf | MervinPraison/PraisonAI | 2026-06-18 | — | server base URL from configuration fetched unchecked | off_list | requests | ? |   |   |
| GHSA-6h9p-93hq-q7h6 | MervinPraison/PraisonAI | 2026-06-18 | — | redirect to internal address not re-validated | redirect | requests | ? |   |   |
| GHSA-rjvw-7vvw-549v | MervinPraison/PraisonAI | 2026-06-18 | — | host re-resolved after validation (DNS rebinding) | rebinding | httpx | ? |   |   |
| GHSA-vxgj-xg5c-p4h7 | MervinPraison/PraisonAI | 2026-06-18 | — | host re-resolved after validation (DNS rebinding) | rebinding | urllib | ? |   |   |
| GHSA-wm69-2pc3-rmmf | unclecode/crawl4ai | 2026-06-18 | — | links derived from fetched content fetched without host check | derived_links | — | ? |   |   |
| GHSA-4cc2-g9w2-fhf6 | mvantellingen/python-zeep | 2026-06-19 | https://github.com/mvantellingen/python-zeep/commit/83eb07bc6c84d841329d4f88856fecdba86f753e | URL scheme not restricted | scheme | — | ? |   |   |
| GHSA-c693-x898-5g4h | BerriAI/litellm | 2026-06-21 | — | server base URL from configuration fetched unchecked | off_list | — | ? |   |   |
| GHSA-ffm6-vvph-g5f5 | OpenCTI-Platform/opencti | 2026-06-22 | — | server base URL from configuration fetched unchecked | off_list | — | ? |   |   |
| GHSA-h8rc-w822-q8vq | openstack/swift | 2026-06-23 | https://github.com/openstack/swift/commit/75b050fdb1d1a6096f3765faa3b2059e28065d13 | redirect to internal address not re-validated | redirect | — | ? |   |   |
| GHSA-54vg-pfh7-jq95 | Netflix/lemur | 2026-06-25 | — | links derived from fetched content fetched without host check | derived_links | requests | ? |   |   |
| GHSA-v2wp-frmc-5q3v | Netflix/lemur | 2026-06-25 | https://github.com/Netflix/lemur/commit/872f6e282542352f2bf3f6e2bcc504ab81e1843d | host re-resolved after validation (DNS rebinding) | rebinding | other | ? |   |   |
| GHSA-cg7w-rg45-pc59 | pydantic/pydantic-ai | 2026-06-26 | https://github.com/pydantic/pydantic-ai/commit/1add06179ba4de259f7ab977620b697b7209f7e4 | internal address allow-list misses an address encoding | off_list | — | ? |   |   |
| GHSA-794r-5rp2-fpg8 | flytohub/flyto-core | 2026-07-06 | — | internal address allow-list misses an address encoding | off_list | aiohttp | ? |   |   |
| GHSA-jgx9-jr5x-mvpv | open-webui/open-webui | 2026-07-07 | — | image URL from user input fetched without host check | off_list | requests | ? |   |   |
| GHSA-vmfc-9982-2m45 | WeblateOrg/weblate | 2026-07-07 | https://github.com/WeblateOrg/weblate/pull/19768 | internal address block-list incomplete | off_list | — | ? |   |   |
| GHSA-m5x5-28jr-gpjj | pyload/pyload | 2026-07-09 | — | internal address allow-list misses an address encoding | off_list | other | ? |   |   |
| GHSA-489g-7rxv-6c8q | sooperset/mcp-atlassian | 2026-07-10 | — | host re-resolved after validation (DNS rebinding) | rebinding | — | ? |   |   |
| GHSA-mr4r-hcgx-8p4h | crewAIInc/crewAI | 2026-07-14 | https://github.com/crewAIInc/crewAI/commit/5d4851eac797cafc45b726f65747fe2c9520fc42 | redirect to internal address not re-validated | redirect | — | ? |   |   |
| GHSA-824w-x939-6cmc | tensorzero/tensorzero | 2026-07-15 | https://github.com/tensorzero/tensorzero/commit/0abbc838bae3394fe7491dad7009670d4e3b6cf8 | URL scheme not restricted | scheme | — | ? |   |   |
| GHSA-45gf-fjxp-cjpq | pipeboard-co/meta-ads-mcp | 2026-07-17 | https://github.com/pipeboard-co/meta-ads-mcp/commit/7d9926336bbdac6285a988d043c4ccfe126c94c5 | download URL from user input fetched without host check | off_list | httpx | ? |   |   |
| GHSA-frvj-c5qp-xj4w | open-webui/open-webui | 2026-07-24 | https://github.com/open-webui/open-webui/commit/05098d25a58d03738e01c4e85e8852c3b4ad849c | internal address block-list incomplete | off_list | aiohttp | ? |   |   |
| GHSA-954p-556p-r752 | koxudaxi/datamodel-code-generator | 2026-07-28 | https://github.com/koxudaxi/datamodel-code-generator/commit/5fdba4a09f2d7a9996a504975b7ef7d63e3715bb | redirect to internal address not re-validated | redirect | other | ? |   |   |
| GHSA-rfr2-mq9m-x2qx | koxudaxi/datamodel-code-generator | 2026-07-28 | https://github.com/koxudaxi/datamodel-code-generator/commit/5fdba4a09f2d7a9996a504975b7ef7d63e3715bb | excluded (duplicate) | redirect | httpx | ? |   |   |
| GHSA-vx7x-vcc2-c44g | koxudaxi/datamodel-code-generator | 2026-07-28 | https://github.com/koxudaxi/datamodel-code-generator/commit/25c8b7e497419eb20b230fa3318c04f9bebc5a6f | host re-resolved after validation (DNS rebinding) | rebinding | httpx | ? |   |   |
| GHSA-4jc5-g844-4x33 | Linuxfabrik/lib | 2026-07-30 | https://github.com/Linuxfabrik/lib/commit/6573ff9347e541200305d278d2663d2e54e052ff | redirect to internal address not re-validated | redirect | httpx | ? |   |   |
| GHSA-c9hr-64h3-gxpc | flytohub/flyto-core | 2026-07-30 | https://github.com/flytohub/flyto-core/commit/0a0a528520ec18f5a21f1ddf858a71cc1edfb6e9 | redirect to internal address not re-validated | redirect | aiohttp | ? |   |   |
| GHSA-jx74-cqjv-2c67 | flytohub/flyto-core | 2026-07-30 | https://github.com/flytohub/flyto-core/commit/0a0a528520ec18f5a21f1ddf858a71cc1edfb6e9 | excluded (duplicate) | off_list | — | ? |   |   |
| GHSA-pgwh-4jj4-qm8v | flytohub/flyto-core | 2026-07-30 | https://github.com/flytohub/flyto-core/commit/0a0a528520ec18f5a21f1ddf858a71cc1edfb6e9 | excluded (duplicate) | off_list | aiohttp | ? |   |   |
| GHSA-qvv7-cg9c-w4x3 | nltk/nltk | 2026-07-31 | — | host re-resolved after validation (DNS rebinding) | rebinding | urllib | ? |   |   |
| GHSA-8x5v-cpv7-8jjp | open-webui/open-webui | 2026-08-04 | https://github.com/open-webui/open-webui/commit/1717b493d83c86afa82aa8bc50139250852dd2f3 | internal address allow-list misses an address encoding | off_list | — | ? |   |   |
| GHSA-h6x2-583h-x99r | open-webui/open-webui | 2026-08-04 | — | host re-resolved after validation (DNS rebinding) | rebinding | aiohttp | ? |   |   |
| GHSA-rffm-9q57-q649 | open-webui/open-webui | 2026-08-04 | https://github.com/open-webui/open-webui/commit/5278eb906ebecefc6538a19bc86df09d997e43e6 | links derived from fetched content fetched without host check | derived_links | — | ? |   |   |
| GHSA-w2rx-84hp-gg95 | open-webui/open-webui | 2026-08-04 | https://github.com/open-webui/open-webui/commit/bef63a2ae915571d50d2722a635e8bfa753d7877 | redirect to internal address not re-validated | redirect | other | ? |   |   |
| GHSA-h7x2-h6g9-p789 | mlflow/mlflow | 2026-08-05 | https://github.com/mlflow/mlflow/commit/96b7d900e14227e0821981409d86f5fb6c59b386 | server base URL from configuration fetched unchecked | off_list | — | ? |   |   |
| GHSA-2jhm-w3mp-jcwr | nltk/nltk | 2026-08-10 | https://github.com/nltk/nltk/commit/4a820afa58810cd05049b6c6eae306694d6cfe65 | URL from user input fetched without host check | — | — | ? |   |   |
| GHSA-h47f-gmjp-m7rr | oscal-compass/compliance-trestle | 2026-08-12 | https://github.com/oscal-compass/compliance-trestle/commit/d107cd16efe8eb15d46be3c1d97f1ec73d32447c | internal address allow-list misses an address encoding | off_list | — | ? |   |   |
| GHSA-h7p7-w5gc-xj3w | pydantic/pydantic-ai | 2026-08-13 | — | download URL from user input fetched without host check | off_list | — | ? |   |   |
| GHSA-9hgc-g3w5-67cm | IBM/mcp-context-forge | 2026-08-14 | — | host re-resolved after validation (DNS rebinding) | rebinding | httpx | ? |   |   |
| GHSA-7gwp-5pfp-969j | mlflow/mlflow | 2026-08-17 | https://github.com/mlflow/mlflow/commit/ba949522477cbd5915aa55d29b0cfad7d5ddf939 | redirect to internal address not re-validated | redirect | — | ? |   |   |
| GHSA-95px-34x5-p37h | MobSF/Mobile-Security-Framework-MobSF | 2026-08-18 | https://github.com/MobSF/Mobile-Security-Framework-MobSF/commit/62563ca429a75b3e5d47a13b958e1d2e7d5e2bbf | redirect to internal address not re-validated | redirect | requests | ? |   |   |
| GHSA-f3qq-49m6-rw8f | Netflix/lemur | 2026-08-18 | https://github.com/Netflix/lemur/commit/ed504a830f38a83825b1570302e9f38d6553938a | redirect to internal address not re-validated | redirect | requests | ? |   |   |
| GHSA-v5rc-cpwc-cfpr | Netflix/lemur | 2026-08-18 | https://github.com/Netflix/lemur/commit/edca0390f930344d65ff4ca37a669c2320e3dfad | internal address block-list incomplete | off_list | — | ? |   |   |
| GHSA-xpmj-wjcp-6pww | Netflix/lemur | 2026-08-18 | https://github.com/Netflix/lemur/commit/6dcb19b6d6004e97796d6a0344b130b2ba57f050 | download URL from user input fetched without host check | off_list | other | ? |   |   |
| GHSA-p77j-g7h5-r2vw | geolens-io/geolens | 2026-08-19 | https://github.com/geolens-io/geolens/pull/243 | host re-resolved after validation (DNS rebinding) | rebinding | — | ? |   |   |
| GHSA-5p3m-vhh6-9236 | eidetic-labs/stigmem | 2026-08-20 | https://github.com/eidetic-labs/stigmem/pull/726 | webhook or callback URL fetched without host check | off_list | httpx | ? |   |   |
| GHSA-5r34-2g38-6569 | MervinPraison/PraisonAI | 2026-08-25 | https://github.com/MervinPraison/PraisonAI/commit/2f9677abb2ea68eab864ee8b6a828fd0141612e1 | redirect to internal address not re-validated | redirect | httpx | ? |   |   |
| GHSA-8cp3-qxj6-px34 | universal-tool-calling-protocol/python-utcp | 2026-08-25 | https://github.com/universal-tool-calling-protocol/python-utcp/commit/fc3268e2a62e1181f91a63faf0a9bcee7639db29 | server base URL from configuration fetched unchecked | off_list | aiohttp | ? |   |   |
| GHSA-8hjw-25cg-g52h | MervinPraison/PraisonAI | 2026-08-25 | https://github.com/MervinPraison/PraisonAI/commit/2f9677abb2ea68eab864ee8b6a828fd0141612e1 | excluded (duplicate) | redirect | httpx | ? |   |   |
| GHSA-9qhg-99ww-9mqc | universal-tool-calling-protocol/python-utcp | 2026-08-25 | https://github.com/universal-tool-calling-protocol/python-utcp/commit/fc3268e2a62e1181f91a63faf0a9bcee7639db29 | excluded (duplicate) | redirect | aiohttp | ? |   |   |
| GHSA-hmfx-4v44-9qw9 | MervinPraison/PraisonAI | 2026-08-25 | https://github.com/MervinPraison/PraisonAI/commit/2f9677abb2ea68eab864ee8b6a828fd0141612e1 | excluded (duplicate) | rebinding | httpx | ? |   |   |
| GHSA-hvfh-5mj3-5f3j | Chainlit/chainlit | 2026-08-25 | https://github.com/Chainlit/chainlit/commit/0565fd0eccb915fce159929598b053ed79f6e0c9 | redirect to internal address not re-validated | redirect | other | ? |   |   |
| GHSA-ppx3-28rw-8fpf | universal-tool-calling-protocol/python-utcp | 2026-08-25 | https://github.com/universal-tool-calling-protocol/python-utcp/commit/fc3268e2a62e1181f91a63faf0a9bcee7639db29 | excluded (duplicate) | redirect | aiohttp | ? |   |   |
| GHSA-rg5q-pp8p-f7jm | MervinPraison/PraisonAI | 2026-08-25 | https://github.com/MervinPraison/PraisonAI/commit/2f9677abb2ea68eab864ee8b6a828fd0141612e1 | excluded (duplicate) | off_list | httpx | ? |   |   |
| GHSA-vg6p-v9vm-6fgj | MervinPraison/PraisonAI | 2026-08-25 | https://github.com/MervinPraison/PraisonAI/commit/2f9677abb2ea68eab864ee8b6a828fd0141612e1 | excluded (duplicate) | redirect | urllib | ? |   |   |
| GHSA-x44h-65qv-cw74 | MervinPraison/PraisonAI | 2026-08-25 | https://github.com/MervinPraison/PraisonAI/commit/2f9677abb2ea68eab864ee8b6a828fd0141612e1 | excluded (duplicate) | off_list | requests | ? |   |   |
| GHSA-3gqm-fcw5-w839 | nltk/nltk | 2026-09-02 | https://github.com/nltk/nltk/commit/4a820afa58810cd05049b6c6eae306694d6cfe65 | excluded (duplicate) | rebinding | urllib | ? |   |   |
| GHSA-4mvj-m6j5-pmf7 | Unstructured-IO/unstructured | 2026-09-03 | https://github.com/Unstructured-IO/unstructured/commit/445c95735c4045057f51f399bc04c657751923bd | redirect to internal address not re-validated | redirect | requests | ? |   |   |
| GHSA-4hhp-h66f-j5j7 | vllm-project/vllm | 2026-09-08 | https://github.com/vllm-project/vllm/commit/54503ecec0f3ac31e5ecfc5f28652e4cc42307b5 | URL scheme not restricted | scheme | requests | ? |   |   |
| GHSA-6ww7-3frv-cqxh | nltk/nltk | 2026-09-08 | https://github.com/nltk/nltk/commit/767333a005a1cd3d82d2029215f2dbe66a5844d9 | proxy setting from user input routes outbound traffic | other | urllib | ? |   |   |
| GHSA-5x7x-4c3c-qf5w | open-webui/open-webui | 2026-09-09 | https://github.com/open-webui/open-webui/commit/e3e4bd87df6fc629e7e22081d980d55a7632b8b7 | redirect to internal address not re-validated | redirect | aiohttp | ? |   |   |
| GHSA-jf6q-chmf-3h3v | Kozea/WeasyPrint | 2026-09-09 | — | URL scheme not restricted | scheme | — | ? |   |   |
| GHSA-34r3-9m95-vq73 | open-webui/open-webui | 2026-09-10 | https://github.com/open-webui/open-webui/commit/e3e4bd87df6fc629e7e22081d980d55a7632b8b7 | excluded (duplicate) | off_list | — | ? |   |   |
| GHSA-4v28-j6q3-5m4r | open-webui/open-webui | 2026-09-10 | https://github.com/open-webui/open-webui/commit/27402ff210bfa253445720920dfb86b15a00327b | host re-resolved after validation (DNS rebinding) | rebinding | other | ? |   |   |
| GHSA-hx8v-g79f-8w5f | BerriAI/litellm | 2026-09-17 | https://github.com/BerriAI/litellm/commit/47214be317f45a2d2ac08258362e0481411eb427 | proxy setting from user input routes outbound traffic | other | — | ? |   |   |
| GHSA-39wr-7q6h-cf68 | InternLM/lmdeploy | 2026-09-18 | — | internal address block-list incomplete | off_list | requests | ? |   |   |
| GHSA-49xv-9743-pw8w | sooperset/mcp-atlassian | 2026-09-22 | https://github.com/sooperset/mcp-atlassian/commit/b041733473f95119dd539542a43c280737a8e460 | host re-resolved after validation (DNS rebinding) | rebinding | requests | ? |   |   |
| GHSA-4ghv-53cq-7wp3 | home-assistant/core | 2026-09-22 | https://github.com/home-assistant/core/pull/162941 | redirect to internal address not re-validated | redirect | aiohttp | ? |   |   |
| GHSA-5wf4-jqxh-8gm3 | sooperset/mcp-atlassian | 2026-09-22 | https://github.com/sooperset/mcp-atlassian/commit/b041733473f95119dd539542a43c280737a8e460 | excluded (duplicate) | off_list | — | ? |   |   |
| GHSA-6529-c226-h328 | sooperset/mcp-atlassian | 2026-09-22 | https://github.com/sooperset/mcp-atlassian/commit/b041733473f95119dd539542a43c280737a8e460 | excluded (duplicate) | redirect | requests | ? |   |   |
| GHSA-ch3g-4xvr-674q | opencve/opencve | 2026-09-22 | https://github.com/opencve/opencve/commit/0af7f894debc95c67fa53e7ba5a6cdecb10c34f0 | webhook or callback URL fetched without host check | off_list | — | ? |   |   |
| GHSA-hgcf-4mq8-5266 | sooperset/mcp-atlassian | 2026-09-22 | https://github.com/sooperset/mcp-atlassian/commit/b041733473f95119dd539542a43c280737a8e460 | excluded (duplicate) | off_list | — | ? |   |   |
| GHSA-v9m3-wfh8-5646 | sooperset/mcp-atlassian | 2026-09-22 | https://github.com/sooperset/mcp-atlassian/commit/b041733473f95119dd539542a43c280737a8e460 | excluded (duplicate) | redirect | requests | ? |   |   |
| GHSA-vv3m-f8x4-7377 | HKUDS/LightRAG | 2026-09-22 | https://github.com/HKUDS/LightRAG/pull/3426 | internal address allow-list misses an address encoding | off_list | — | ? |   |   |
| GHSA-9v7f-9g4p-ffgj | jpadilla/pyjwt | 2026-09-29 | https://github.com/jpadilla/pyjwt/commit/0a795b8e1f6ef08f634aa7086fc41cc6d5ce3e56 | redirect to internal address not re-validated | redirect | — | ? |   |   |
| GHSA-3cv6-jpf6-8222 | BerriAI/litellm | 2026-09-30 | https://github.com/BerriAI/litellm/pull/36011 | redirect to internal address not re-validated | redirect | — | ? |   |   |
| GHSA-3325-v43h-43rv | jupyterlab/jupyterlab | 2026-10-01 | https://github.com/jupyterlab/jupyterlab/commit/9e1951e57da499ca66ef5e0caf68e71ad2e3d1a5 | internal address block-list incomplete | off_list | — | ? |   |   |
| GHSA-jqmf-mx4f-hfr6 | HKUDS/Vibe-Trading | 2026-10-02 | https://github.com/HKUDS/Vibe-Trading/commit/9454d4a27a763b80e1d6eb5763b86c88e9e4e714 | redirect to internal address not re-validated | redirect | requests | ? |   |   |
| GHSA-qx36-8mw2-4r3x | mongodb/mongo-python-driver | 2026-10-05 | https://github.com/mongodb/mongo-python-driver/pull/3066 | redirect to internal address not re-validated | redirect | — | ? |   |   |
| GHSA-j8f7-x8jm-wmm4 | langflow-ai/langflow | 2026-10-06 | https://github.com/langflow-ai/langflow/commit/94859df33acd70b2a1f816e26d68f5e89a7e5639 | redirect to internal address not re-validated | redirect | requests | ? |   |   |
| GHSA-6g59-gm2v-qhvq | MervinPraison/PraisonAI | 2026-10-07 | — | links derived from fetched content fetched without host check | derived_links | — | ? |   |   |
| GHSA-pc36-qwjq-x68c | docling-project/docling | 2026-10-07 | https://github.com/docling-project/docling/commit/5e469137f275ffc443306a30d12a3a45bceb80fb | host re-resolved after validation (DNS rebinding) | rebinding | urllib | ? |   |   |
| GHSA-2v95-h47v-g4x9 | indico/indico | 2026-10-08 | https://github.com/indico/indico/commit/44540e70ab4e20a12f14ddba5218a33749a86736 | proxy setting from user input routes outbound traffic | other | — | ? |   |   |
| GHSA-4w49-gwv8-fpjg | MervinPraison/PraisonAI | 2026-10-08 | — | webhook or callback URL fetched without host check | off_list | httpx | ? |   |   |
| GHSA-qg25-6gc4-48mg | MervinPraison/PraisonAI | 2026-10-08 | — | host re-resolved after validation (DNS rebinding) | rebinding | httpx | ? |   |   |
| GHSA-vmxc-h2x2-jmf3 | pydantic/pydantic-ai | 2026-10-08 | https://github.com/pydantic/pydantic-ai/pull/8401 | internal address allow-list misses an address encoding | off_list | — | ? |   |   |
| GHSA-p3pr-8f3m-4qp8 | pyload/pyload | 2026-10-09 | https://github.com/pyload/pyload/commit/989a551d2ae0c00b0d2c7baf6d850180c9b46559 | server base URL from configuration fetched unchecked | off_list | other | ? |   |   |
| GHSA-2wqp-q3c6-ccj5 | mlflow/mlflow | 2026-10-23 | https://github.com/mlflow/mlflow/commit/bac30b4148c4f40045b4d4db07ae60ab3838803f | URL taken from a request header fetched unchecked | off_list | requests | ? |   |   |
| GHSA-rw7v-4hrq-x6r9 | py-pdf/fpdf2 | 2026-10-27 | https://github.com/py-pdf/fpdf2/pull/1824 | image URL from user input fetched without host check | off_list | — | ? |   |   |
| GHSA-rwrf-2pqf-9j8j | modelcontextprotocol/python-sdk | 2026-10-27 | https://github.com/modelcontextprotocol/python-sdk/pull/3394 | URL scheme not restricted | scheme | — | ? |   |   |
| GHSA-x4rv-c3wx-4cr8 | authlib/authlib | 2026-10-27 | https://github.com/authlib/authlib/pull/949 | URL scheme not restricted | scheme | requests | ? |   |   |
| GHSA-56v3-jrq2-4q9m | dmunozv04/iSponsorBlockTV | 2026-11-19 | https://github.com/dmunozv04/iSponsorBlockTV/commit/7d315115f41523632588fb0b22d46d85807172b7 | internal address block-list incomplete | off_list | — | ? |   |   |
| GHSA-2mr3-rxrq-238c | flytohub/flyto-core | 2026-11-20 | https://github.com/flytohub/flyto-core/commit/bbb6f1cfec22fee1ea0e6ecf1129d7103c85e09f | URL taken from a request header fetched unchecked | off_list | — | ? |   |   |
| GHSA-6pm8-6f34-9v3g | flytohub/flyto-core | 2026-11-20 | https://github.com/flytohub/flyto-core/commit/bf748df864d348004cf45d830bc59f62c5c4a58a | host re-resolved after validation (DNS rebinding) | rebinding | aiohttp | ? |   |   |
| GHSA-86mf-q4h5-69gp | tony/django-docutils | 2026-11-20 | https://github.com/tony/django-docutils/pull/457 | URL scheme not restricted | scheme | — | ? |   |   |
| GHSA-pfg2-w999-497v | flytohub/flyto-core | 2026-11-20 | https://github.com/flytohub/flyto-core/commit/bf748df864d348004cf45d830bc59f62c5c4a58a | excluded (duplicate) | rebinding | aiohttp | ? |   |   |
