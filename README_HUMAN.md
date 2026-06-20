# ReconEcoboost

## 1. How to use

### Set scope
Set scope in /config/scope.yaml:

    If exist *.domain.com -> fuzzing subdomain

    If do not exit *.domain.com or only exist domain.com -> Skip fuzzing subdomain step

### Config tool

Config in /config/tools.yaml:

    Can setup rate limit for each tool

    Set up what method use to fuzzing directory at methods

### Wordlist

Setup wordlist in /config/wordlists.yaml

    Can setup wordlist for fuzzing subdomain/vhost and directory

### Config data pass to agent in /config/ai.yaml

    context_top_n: get top rank target and pass to Agent

    ontext_scope: global -> only get top N target in all scope (in all subdomain)

    ontext_scope: per_host ->  get top N target per host in scope (scope has many subdomain)

### ARGV Option

--ai-mode:

    off -> Do not use AI agent, just run tool to recon

    analyze -> AI analysis only, analyze the tools result

    pentest -> analyze and pentest the target from the tool result

--run-id:

    - choose the result id of the scan result then pass to the AI Agent


Example:

```
reconecoboost example.com --run --ai-mode off                                  # tools only
reconecoboost example.com --run --ai-mode analyze                              # tools + recon intel
reconecoboost example.com --run --ai-mode pentest                              # tools + intel + AI pentest
reconecoboost example.com --run --no-ai                                        # tools only
reconecoboost example.com --run --ai-mode analyze --run-id 123123123           # get result from 123123123 resultID and analyze
reconecoboost example.com --run --ai-mode pentest --run-id 123123123           # get result from 123123123 resultID and pentest
```

## View result

    All result show run /result/<id>

    Data after run all tool -> triage saved in triage.json and triage.txt (beauti view)

