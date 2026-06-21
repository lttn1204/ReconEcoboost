# ReconEcoboost


## 1. Flow 


## 2. How to use

### Set scope
Set scope in /config/scope.yaml:

    If exist *.domain.com -> fuzzing subdomain

    If do not exit *.domain.com or only exist domain.com -> Skip fuzzing subdomain step

### Config tool

Config in /config/tools.yaml:

    Can setup rate limit for each tool

    Set up what method use to fuzzing directory at methods

    Set up which severity saved in nuclei 

### Wordlist

Setup wordlist in /config/wordlists.yaml

    Can setup wordlist for fuzzing subdomain/vhost and directory

    Set up dnsx wordlist

### Config data pass to agent in /config/ai.yaml

    context_top_n: get top rank target and pass to Agent

    ontext_scope: global -> only get top N target in all scope (in all subdomain)

    ontext_scope: per_host ->  get top N target per host in scope (scope has many subdomain)

    prompt_version -> version promt use to promt agent

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

## Another Options on /config/pipeline.yaml

#### DNS Resolve
    dns_resolve: brute: enable:true -> Bruteforce resolve DNS
    
    dns_resolve: brute: depth -> brut force recursive. EX dept =2  -> subdomain of subdomain

#### Secret Scan
    js_intel:  enabled: true  -> scan secret and analyze, if found another url/uri (not discover from above tool) -> fetch and scan it too

    js_intel:  enabled: false  -> only scan secret in url get from above tool


#### content_subdomains
    content_subdomains: true -> after fuzzing, fetch the content of discover url -> get new subdomain  -> Go back and scan that URL.
    
    Can configure scan loops or depth in discovery.


## View result /result/\<id\>

    All result show run /result/<id>

    Data after run all tool -> triage saved in triage.json and triage.txt (beauti view)

