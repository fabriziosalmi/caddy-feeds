# caddy-waf feeds

This repository contains a workflow to daily update and release IP blacklist, DNS blacklist and OWASP rules for the [caddy-waf](https://github.com/fabriziosalmi/caddy-waf) project. This is useful to avoid the hassle to mantain updated lists for caddy-waf features like IP, DNS and regex rules blacklisting.

## Lists

### IP blacklist

```
https://github.com/fabriziosalmi/caddy-feeds/releases/download/latest/ip_blacklist.txt
```


### DNS blacklist

```
https://github.com/fabriziosalmi/caddy-feeds/releases/download/latest/dns_blacklist.txt
```

### OWASP rules
> [!WARNING]
> You can use IP and DNS blacklist but DON'T rely on the generated rules files at the moment since it will need additional fixes and improvements. I suggest to start with the [base ruleset](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules.go) provided by the caddy-waf repository.

```
https://github.com/fabriziosalmi/caddy-feeds/releases/download/latest/rules.json
```
