# Holdout selection log

## Method

- Source: sparse clone of github/advisory-database (advisories/github-reviewed/2025 and 2026, HEAD as of 2026-11-23). Grepped for `model context protocol|mcp` -> 543 advisories; kept those whose CWE tags map to an in-scope class (CWE-77/78/88/22/23/24/35/36/59/73/918/94/95/89/306/287/288/798/259/321/1188) -> 318; removed 27 rule-4 repos by name -> 291 remaining.

- Walked the 291 in publication-date order (ties broken by CVE id) and evaluated each against rules 1-5.

- Diversity rule (declared before selection, applied by class only, never by difficulty): at most 6 advisories per vulnerability class, so the set spreads across classes as the brief asks. Advisories that passed rules 1-4 but came after their class hit 6 are marked `REJECT cap`.

- Rule 3 check: each repo was cloned over HTTPS (blobless). vuln_ref and fixed_ref were confirmed to exist and be reachable from a remote branch. vuln_ref was confirmed to be an ancestor of fixed_ref, and the listed files were confirmed to exist at vuln_ref. Where the advisory gave no patch, the fix commit was found in repo history and the diff was checked.

- Selection stopped once 24 were accepted (at GHSA-89g2-xw5c-v95p, published 2026-05-05).


## Evaluated advisories (in order)

| # | GHSA | Decision | Reason |
|---|---|---|---|
| 1 | GHSA-qgp8-v765-qxx9 | REJECT r1 | @cloudflare/workers-oauth-provider is an OAuth library, not an MCP server |
| 2 | GHSA-vh4h-fvqf-q9wv | REJECT r1 | duplicate advisory of the above OAuth library |
| 3 | GHSA-frq9-3hp2-xvxg | ACCEPT (h01) | SSRF #1 |
| 4 | GHSA-7f8r-222p-6f5g | REJECT r1 | MCP Inspector is a developer client/proxy tool, not an MCP server |
| 5 | GHSA-6f6r-m9pv-67jw | ACCEPT (h02) | command injection #1 |
| 6 | GHSA-gjv4-ghm7-q58q | ACCEPT (h03) | command injection #2 |
| 7 | GHSA-5w57-2ccq-8w95 | ACCEPT (h04) | command injection #3 |
| 8 | GHSA-xj5p-8h7g-76m7 | ACCEPT (h05) | command injection #4 |
| 9 | GHSA-vf9j-h32g-2764 | ACCEPT (h06) | command injection #5 |
| 10 | GHSA-2vv2-3x8x-4gv7 | REJECT r1 | Flowise is an LLM app builder, not an MCP server |
| 11 | GHSA-p6rm-483j-37jf | REJECT r1 | wong2/mcp-cli is an MCP client/inspector CLI |
| 12 | GHSA-45qj-4xq3-3c45 | ACCEPT (h07) | command injection #6 (cap reached; 2nd advisory for this repo) |
| 13 | GHSA-3ch2-jxxc-v4xf | REJECT cap | passes r1-r4 (refs 32e03b8 -> 48c26bb verified) but class cap of 6 for command injection already reached |
| 14 | GHSA-g9hg-qhmf-q45m | REJECT r1 | MCP Inspector (client tool); XSS-to-exec |
| 15 | GHSA-g5cg-6c7v-mmpw | ACCEPT (h08) | SSRF #2 |
| 16 | GHSA-hjm5-xgj8-vwj6 | REJECT cap | passes r1-r4 (v0.1.11 -> v0.1.12 verified) but command-injection cap reached |
| 17 | GHSA-4hqq-7q79-932p | REJECT cap | passes r1-r4 (v0.1.11 -> v0.1.12 verified) but command-injection cap reached |
| 18 | GHSA-3gcm-f6qx-ff7p | REJECT r1 | Flowise |
| 19 | GHSA-6933-jpx5-q87q | REJECT r1 | Flowise (MCP client config) |
| 20 | GHSA-9pw5-wx67-q964 | REJECT r1 | sequa-mcp is a stdio-to-remote proxy; the flaw is in its client-side OAuth flow (code derived from mcp-remote, which is also excluded by r4) |
| 21 | GHSA-gxw4-4fc5-9gr5 | REJECT cap | passes r1-r4 (v0.6.2 -> v0.6.3 verified) but command-injection cap reached |
| 22 | GHSA-hmgh-466j-fx4c | REJECT r1 | Flowise |
| 23 | GHSA-rj5c-58rq-j5g5 | REJECT r1 | FastMCP is a framework/SDK for building MCP servers; flaw in its CLI installer |
| 24 | GHSA-c2jp-c369-7pvx | REJECT r1/r2 | FastMCP framework; confused-deputy OAuth is not an in-scope class |
| 25 | GHSA-27m7-ffhq-jqrm | REJECT cap | mcp-watch command injection; command-injection cap reached (not further evaluated) |
| 26 | GHSA-w48q-cv73-mx4w | REJECT r1 | MCP TypeScript SDK, not a server; DNS-rebinding default |
| 27 | GHSA-9h52-p55h-vw2f | REJECT r1 | MCP Python SDK, not a server |
| 28 | GHSA-g2jx-37x6-6438 | ACCEPT (h09) | hardcoded secret #1 |
| 29 | GHSA-wvxp-jp4w-w8wg | REJECT cap | passes r1-r4 (0ab947f -> d091107 verified) but command-injection cap reached |
| 30 | GHSA-8fxj-2g9q-8fjw | ACCEPT (h10) | SSRF #3 (advisory lists last_affected 1.0.2; fix commit located in repo history) |
| 31 | GHSA-5cgr-j3jf-jw3v | REJECT r4 | mcp-server-git lives in modelcontextprotocol/servers |
| 32 | GHSA-9xwc-hfwc-8w59 | REJECT r4 | mcp-server-git (modelcontextprotocol/servers) |
| 33 | GHSA-j22h-9j4x-23w5 | REJECT r4 | mcp-server-git (modelcontextprotocol/servers) |
| 34 | GHSA-f43r-cc68-gpx4 | REJECT r1 | Langflow is not an MCP server |
| 35 | GHSA-rwc2-f344-q6w6 | REJECT cap | serverless MCP server command injection (79f2d16 -> 681ca03 verified) but command-injection cap reached |
| 36 | GHSA-h4rf-624j-gj33 | REJECT r3 | terminal-controller-mcp: no fix in repo (last commit predates advisory) |
| 37 | GHSA-j893-m93w-jwjw | REJECT r3 | fast-filesystem-mcp: isPathAllowed startsWith check unchanged at HEAD; no fixed ref |
| 38 | GHSA-78h3-63c4-5fqc | REJECT r1/r3 | WeKnora is a Go RAG framework (MCP client side) |
| 39 | GHSA-mwr6-3gp8-9jmj | REJECT r1 | orval is an OpenAPI code generator |
| 40 | GHSA-7qm7-455j-5p63 | REJECT r1 | enclave-vm is a JS sandbox library |
| 41 | GHSA-232v-j27c-5pp6 | REJECT r1 | MCPJam inspector is an MCP client/testing tool |
| 42 | GHSA-4gpc-rhpj-9443 | REJECT r1 | Lobe Chat is a chat client |
| 43 | GHSA-h526-wf6g-67jv | REJECT r1 | orval code generator |
| 44 | GHSA-28qq-5f47-r5x2 | REJECT dup/cap | duplicate advisory (gemini-mcp-tool); also command-injection cap reached |
| 45 | GHSA-8jx2-rhfh-q928 | REJECT cap | godot-mcp (90b907a -> 21c785d verified) but command-injection cap reached |
| 46 | GHSA-2g7v-hghf-grg4 | REJECT cap | mcp-maigret (v1.0.12 -> v1.0.13 verified) but command-injection cap reached |
| 47 | GHSA-84fx-pwf3-7777 | REJECT cap | xcode-mcp-server (f3419f0 -> 11f8d6b verified) but command-injection cap reached |
| 48 | GHSA-6fgp-m6q4-j3q5 | REJECT r3 | mcp-run-python: repo archived, --allow-net unchanged; no fixed ref |
| 49 | GHSA-vjqx-cfc4-9h6v | REJECT r4 | mcp-server-git (modelcontextprotocol/servers) |
| 50 | GHSA-xc68-rrqc-qgq3 | REJECT cap | nmap-mcp-server (bee6d23 -> 30a6b9e verified) but command-injection cap reached |
| 51 | GHSA-jjgj-cpp9-cvpv | REJECT r1 | OpenClaw is an AI assistant (MCP host), not an MCP server |
| 52 | GHSA-g8r9-g2v8-jv6f | REJECT r1 | GitHub Copilot CLI |
| 53 | GHSA-r55h-3rwj-hcmg | REJECT r1/r3 | WeKnora (Go, MCP client config) |
| 54 | GHSA-hhfx-wfvq-7g9c | REJECT r3 | Azure MCP Server is C#/.NET |
| 55 | GHSA-xjgw-4wvw-rgm4 | ACCEPT (h11) | path traversal #1 |
| 56 | GHSA-7r34-79r5-rcc9 | ACCEPT (h12) | SSRF #4 (2nd and last advisory for this repo) |
| 57 | GHSA-fmfg-9g7c-3vq7 | ACCEPT (h13) | SSRF #5 (fix commit located between v6.7.2 and v7.0.0) |
| 58 | GHSA-qp4c-xg64-7c6x | REJECT r1 | Backstage auth backend plugin |
| 59 | GHSA-3xm7-qw7j-qc8v | ACCEPT (h14) | SSRF #6 (cap reached); vuln v0.4.83, fixed v0.4.85 covers both base_url and sparql fixes |
| 60 | GHSA-wvr4-3wq4-gpc5 | ACCEPT (h15) | missing auth #1 (MCP-connect / mcp-bridge, an HTTP bridge that serves MCP; fix located in 'Merge commit from fork') |
| 61 | GHSA-3p2m-h2v6-g9mx | ACCEPT (h16) | path traversal #2 |
| 62 | GHSA-h6c2-x2m2-mwhf | REJECT r3 | nginx-ui is Go |
| 63 | GHSA-m8x7-r2rg-vh5g | REJECT r1 | FastMCP framework CLI |
| 64 | GHSA-vv7q-7jx5-f767 | REJECT r1 | FastMCP framework OpenAPI provider |
| 65 | GHSA-6fpf-248c-m7wm | REJECT r3 | Sliver is Go |
| 66 | GHSA-xw59-hvm2-8pj6 | REJECT r1/r3 | Go SDK |
| 67 | GHSA-prmx-7v35-7q82 | REJECT cap | a11y-mcp SSRF (19fcc94 -> e3e11c9 verified) but SSRF cap of 6 reached |
| 68 | GHSA-wx4p-jr66-jfp9 | REJECT cap | command-injection cap |
| 69 | GHSA-xqv9-qr76-hfq2 | REJECT cap | command-injection cap |
| 70 | GHSA-v6ph-xcq9-qxxj | REJECT r1 | mcp-from-openapi / FrontMCP SDK library |
| 71 | GHSA-4ggg-h7ph-26qr | REJECT cap | n8n-mcp SSRF (v2.47.3 -> v2.47.4 verified) but SSRF cap reached |
| 72 | GHSA-3xp3-pr8x-f755 | REJECT cap | command-injection cap |
| 73 | GHSA-crh9-3gjh-m6gc | REJECT cap | SSRF cap |
| 74 | GHSA-75hx-xj24-mqrw | ACCEPT (h17) | missing auth #2 |
| 75 | GHSA-fgmx-xfp3-w28p | REJECT cap | command-injection cap |
| 76 | GHSA-c4hg-6933-x62x | REJECT r3 | Apache SkyWalking MCP is Go |
| 77 | GHSA-xrxf-jgv3-qmrm | REJECT r1 | OpenAI Codex CLI (MCP host) |
| 78 | GHSA-4xqg-gf5c-ghwq | ACCEPT (h18) | argument injection #1 (2nd and last for this repo) |
| 79 | GHSA-j98m-w3xp-9f56 | ACCEPT (h19) | path traversal #3 |
| 80 | GHSA-p4h8-56qp-hpgv | ACCEPT (h20) | argument injection #2 |
| 81 | GHSA-cw73-5f7h-m4gv | REJECT r1 | Upsonic agent framework |
| 82 | GHSA-c9gw-hvqq-f33r | REJECT r1 | Flowise |
| 83 | GHSA-qqvm-66q4-vf5c | REJECT r1 | Flowise |
| 84 | GHSA-qhfq-gvvc-5q6q | ACCEPT (h21) | SQL injection #1 |
| 85 | GHSA-v4p8-mg3p-g94g | REJECT r1 | LiteLLM proxy (MCP client/gateway) |
| 86 | GHSA-q882-jc55-6343 | REJECT r3 | kaggle-mcp: no commits after initial release; no fix |
| 87 | GHSA-vmh7-9c7h-2pgg | REJECT cap | SSRF cap |
| 88 | GHSA-h7xc-4mv8-59fj | REJECT cap | SSRF cap |
| 89 | GHSA-wfr3-hf93-qgg3 | REJECT r3 | mkdocs-mcp-plugin repo not publicly cloneable |
| 90 | GHSA-vc5j-42hh-j3mr | REJECT r3 | notes-mcp: no commits after advisory; no fix |
| 91 | GHSA-56c3-vfp2-5qqj | REJECT cap | SSRF cap |
| 92 | GHSA-86hp-qxqp-w9wv | REJECT cap | command-injection cap |
| 93 | GHSA-gc8w-x73w-p4rh | REJECT cap | command-injection cap |
| 94 | GHSA-gc2j-wpjv-jhrw | ACCEPT (h22) | path traversal #4 (package describes itself as a unified MCP interface; vulnerable code is its MCP server; fix a701296/ea9a212, released v1.6.0) |
| 95 | GHSA-gcmm-c94j-j47x | REJECT r3 | doc-tools-mcp: no commits after 2025-03; no fix |
| 96 | GHSA-hrcw-xc63-g29m | ACCEPT (h23) | path traversal #5 (vulnerable code is pptagent/mcp_server.py) |
| 97 | GHSA-89g2-xw5c-v95p | ACCEPT (h24) | code injection #1 (2nd and last for this repo); target of 24 reached |

## Excluded by rule 4 in prefilter (not evaluated further)

- GHSA-3q26-f695-pp76: REJECT r4 ('npm', '@cyanheads/git-mcp-server')
- GHSA-6xpm-ggf7-wc3p: REJECT r4 ('npm', 'mcp-remote')
- GHSA-6jx8-rcjx-vmwf: REJECT r4 ('npm', '@sunwood-ai-labs/github-kanban-mcp-server')
- GHSA-54j7-grvr-9xwg: REJECT r4 ('npm', 'adb-mcp')
- GHSA-9gm9-c8mq-vq7m: REJECT r4 ('PyPI', 'praisonai')
- GHSA-9qhq-v63v-fv3j: REJECT r4 ('PyPI', 'praisonai')
- GHSA-9mqq-jqxf-grvw: REJECT r4 ('PyPI', 'PraisonAI')
- GHSA-9cr9-25q5-8prj: REJECT r4 ('PyPI', 'PraisonAI')
- GHSA-j7qx-p75m-wp7g: REJECT r4 ('PyPI', 'praisonai')
- GHSA-vmf9-xx9w-86wx: REJECT r4 ('PyPI', 'praisonaiagents'), ('PyPI', 'praisonai')
- GHSA-6h9p-93hq-q7h6: REJECT r4 ('PyPI', 'praisonaiagents')
- GHSA-x227-pf99-vffg: REJECT r4 ('PyPI', 'praisonaiagents')
- GHSA-p75f-6fp4-p57w: REJECT r4 ('PyPI', 'praisonai')
- GHSA-4qq2-2j2x-x62c: REJECT r4 ('npm', 'praisonai')
- GHSA-j4f3-55x4-r6q2: REJECT r4 ('npm', 'praisonai')
- GHSA-9752-mhqh-h34f: REJECT r4 ('npm', 'praisonai')
- GHSA-wj6g-v78p-6fx3: REJECT r4 ('PyPI', 'PraisonAI')
- GHSA-7ww9-85pg-cv4x: REJECT r4 ('PyPI', 'PraisonAI')
- GHSA-r7v3-x45f-g7hp: REJECT r4 ('PyPI', 'PraisonAI')
- GHSA-xpx6-x8c2-mw5w: REJECT r4 ('PyPI', 'praisonai')
- GHSA-hc5v-gxvj-58wh: REJECT r4 ('PyPI', 'praisonai')
- GHSA-4xxv-6wmf-xf45: REJECT r4 ('PyPI', 'praisonaiagents')
- GHSA-79fv-7hq9-w7xg: REJECT r4 ('PyPI', 'praisonai')
- GHSA-2gpf-2492-q9jh: REJECT r4 ('PyPI', 'praisonai')
- GHSA-gj7r-p794-hhq5: REJECT r4 ('Go', 'github.com/kubeshark/kubeshark')
- GHSA-8vf2-hxg5-crqh: REJECT r4 ('Go', 'github.com/kubeshark/kubeshark')
- GHSA-jq3q-62jc-fqq9: REJECT r4 ('npm', 'code-review-mcp-server')

## Not evaluated: listed after the stopping point (target of 24 reached) - 194 advisories

GHSA-pxhg-7xr2-w7xg, GHSA-v228-72c7-fx8j, GHSA-fj4g-2p96-q6m3, GHSA-3r68-x3xc-rxpg, GHSA-8cxw-cc62-q28v, GHSA-8pqq-224h-x875, GHSA-xhrw-5qxx-jpwr, GHSA-j7h9-2jh7-g967, GHSA-95c3-6vvw-4mrq, GHSA-r48c-v28r-pf6v, GHSA-cmrh-wvq6-wm9r, GHSA-52cq-7v8r-62c6, GHSA-8g7g-hmwm-6rv2, GHSA-8jr5-6gvj-rfpf, GHSA-v6wj-c83f-v46x, GHSA-64vr-4gr2-m642, GHSA-94gr-w3q5-rfqr, GHSA-xpww-f6pm-cfhq, GHSA-qjp4-4jvr-xqg3, GHSA-fhh6-4qxv-rpqj, GHSA-g53w-w6mj-hrpp, GHSA-7hgr-7h44-33w2, GHSA-hv85-774v-26fg, GHSA-vrxg-gm77-7q5g, GHSA-63gr-g7jc-v8rg, GHSA-4p62-hqp5-g644, GHSA-6mx4-4h42-r8vh, GHSA-8q5r-mmjf-575q, GHSA-9gw6-46qc-99vr, GHSA-qrx8-25qr-5r7v, GHSA-3pvj-jv98-qhjq, GHSA-4h5r-5jm8-jxjm, GHSA-8fcc-w5hv-4gxv, GHSA-wcpr-6g7x-p44r, GHSA-r2xf-7jw5-pjg6, GHSA-fq4x-789w-jg5h, GHSA-hxpf-9xvq-wph8, GHSA-r78r-rwrf-rjwp, GHSA-w4mc-hhc6-xp28, GHSA-jr33-mw75-7j8f, GHSA-9wxg-vf3r-56hc, GHSA-v52w-28xh-v562, GHSA-jv2h-4p9v-wf5w, GHSA-vcv2-r9jh-99m5, GHSA-mrvx-jmjw-vggc, GHSA-4jcj-7x88-m979, GHSA-c693-x898-5g4h, GHSA-pqrj-4gwg-h5f7, GHSA-73cv-556c-w3g6, GHSA-4hf8-5mjm-rfgq, GHSA-rp72-5v5q-2446, GHSA-q2xp-j85q-883h, GHSA-vwxw-jrg6-9jxv, GHSA-c5r6-m4mr-8q5j, GHSA-pvrj-8cg3-j5f8, GHSA-6gr2-qh89-hxwm, GHSA-jphh-m39h-6gwx, GHSA-84hp-mqvj-3p8h, GHSA-rxw2-pc8j-vxwm, GHSA-g6g7-pvmx-m74p, GHSA-qh2f-99mv-mrcf, GHSA-h9f9-h6gm-wc85, GHSA-g84h-j7jj-x32p, GHSA-pw9m-5jxm-xr6h, GHSA-g38m-r43w-p2q7, GHSA-9h47-pqcx-hjr4, GHSA-q855-8rh5-jfgq, GHSA-52vm-mxx8-f227, GHSA-wmg3-h8mf-wgvr, GHSA-g5r6-gv6m-f5jv, GHSA-wm45-qh3g-v83f, GHSA-489g-7rxv-6c8q, GHSA-2c7f-fxww-6w6c, GHSA-x9vc-9ffq-p3gj, GHSA-3pvh-63gf-j9mw, GHSA-6f5r-5672-72j7, GHSA-pr64-jmmf-jp54, GHSA-62gx-5q78-wrvx, GHSA-8j86-h8gg-797p, GHSA-2v2f-mvfg-ph56, GHSA-45gf-fjxp-cjpq, GHSA-f7wf-v2vw-mpcx, GHSA-7488-6r32-c95q, GHSA-vhf8-cg2h-cg3p, GHSA-4h8q-hh2j-755w, GHSA-8q49-2h5h-434x, GHSA-pgwh-4jj4-qm8v, GHSA-2956-977x-2w3r, GHSA-pqh8-p93p-2rx7, GHSA-p7w7-4929-vpj5, GHSA-c5px-58j2-7fqp, GHSA-c6xh-wv4j-ppv5, GHSA-49m4-vp58-wgc9, GHSA-9hgc-g3w5-67cm, GHSA-76pc-mqxp-3rq5, GHSA-49mq-fc6q-3h46, GHSA-8qf9-62x2-82pp, GHSA-2xhg-73j7-rrgx, GHSA-q87f-qc2r-2gw4, GHSA-wppf-h75h-6pm6, GHSA-rr55-jp92-8wp2, GHSA-j4r7-8ph4-43g3, GHSA-cc2g-gq8c-r332, GHSA-xm98-3vcf-fph7, GHSA-w3fx-mc44-mf6j, GHSA-hvfh-5mj3-5f3j, GHSA-mw6r-2hvm-4rp2, GHSA-m9mq-7m7q-xc6p, GHSA-f5pj-2738-996m, GHSA-3x77-wg38-92r3, GHSA-74hp-mggr-hv58, GHSA-72f3-6w86-7rv3, GHSA-xc9g-j69q-37xw, GHSA-8vh3-g2qg-2h2c, GHSA-vwf3-4xxj-qg6h, GHSA-86m2-fcxq-5q7c, GHSA-jrrm-9hc7-2v3h, GHSA-p8rw-8qj3-hf33, GHSA-83x6-42hr-jc76, GHSA-fg9p-mrxr-hvq7, GHSA-88f2-fpv8-89q2, GHSA-w727-8j6c-2rj4, GHSA-wrj3-vj8c-784f, GHSA-62f5-cp2p-vq95, GHSA-gx45-xrj5-g6c4, GHSA-w7wx-5q49-r59w, GHSA-qjrq-cvv4-3g9w, GHSA-hf57-cqmx-p4gr, GHSA-rqfv-2mw9-78g2, GHSA-65h7-9wrw-629c, GHSA-2h44-8472-frjj, GHSA-cv3r-c5h8-f4g5, GHSA-qg2g-g9w3-m5h8, GHSA-5gm3-9crp-6g3v, GHSA-jgh3-fggc-mcpm, GHSA-798p-78g2-v556, GHSA-jjhp-8crj-mppq, GHSA-wrhw-j3f9-8vc6, GHSA-wv8v-v4c5-v75j, GHSA-f6pj-qv47-g96w, GHSA-cc5h-2pwp-pvcc, GHSA-v9m3-wfh8-5646, GHSA-vc25-24vv-fxxm, GHSA-2xj6-xx86-cwwc, GHSA-mrq8-fv7v-hhjg, GHSA-93xw-j965-9mx3, GHSA-6cr4-ccf3-x7h4, GHSA-f4p7-qx46-wc5j, GHSA-6529-c226-h328, GHSA-p6hp-93wp-fh6p, GHSA-49xv-9743-pw8w, GHSA-mfv2-4wvm-9pgp, GHSA-5wf4-jqxh-8gm3, GHSA-h7wj-5v37-59r2, GHSA-f26r-j276-ggg4, GHSA-6vmq-24h2-pj7j, GHSA-hgcf-4mq8-5266, GHSA-fm8p-53ww-hf6w, GHSA-9gfj-28hw-jchp, GHSA-33jq-p8c2-q3q4, GHSA-3cc2-h3v6-rqpq, GHSA-p23f-cm6q-2qp8, GHSA-x8gv-g2g3-65fj, GHSA-c9xm-49cp-xcr9, GHSA-mc52-mwq4-vfx3, GHSA-w794-rj3p-xv45, GHSA-vc32-4gwf-77xp, GHSA-h4mw-j7qp-8mwm, GHSA-pcc4-rvhr-2pr8, GHSA-953h-535j-jg2v, GHSA-r57g-mc79-8hj2, GHSA-f2ph-cmg5-wxc8, GHSA-px85-f4q5-jh77, GHSA-jwc4-922r-f2rw, GHSA-fq6x-j3g6-xx83, GHSA-c5xx-h28h-f682, GHSA-vqqp-x5qm-5qp4, GHSA-rwrf-2pqf-9j8j, GHSA-7w82-6f9j-v9jp, GHSA-4mfg-r38w-w8fg, GHSA-q344-5v34-gm84, GHSA-9vhv-g5hf-m7m7, GHSA-vvr2-h2jp-838m, GHSA-85gg-2gfq-q95m, GHSA-5m6c-38r8-5w76, GHSA-m932-63jc-4jqq, GHSA-q433-mp6c-8v4f, GHSA-w42c-h7hr-f67p, GHSA-2m9m-6cr5-9x25, GHSA-8hp3-xxrg-v9c8, GHSA-4rj4-rcrq-gr92, GHSA-p34x-fmph-9fjx, GHSA-6pm8-6f34-9v3g, GHSA-24pw-rf5p-mgp7

## Notes
- No advisory was skipped for being hard to detect. Skips are only for rules 1-4, duplicates, or the declared per-class cap.
- Advisories whose CWE tags fall outside the in-scope list were not screened, so in-scope bugs tagged only with unusual CWEs (e.g. CWE-20 alone) may be missing.

