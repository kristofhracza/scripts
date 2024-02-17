# Web scripts

## XSS
`xss.py` will fuzz a specified input in a specified form with a list of payloads defined by the user.       
It also supports cookies, so one can use it on a website where login in needed.

### Usage
```
Usage: xss.py  -u [wesbite] -a [JSON list of attributes] -n [name of input] -f [payload_file]

    REQUIRED:
    -u or --url
    -f or --file
    -n or --name
    -a or --attrs

    OPTIONAL:
    -c or --cookies
    -v or --verbose
```

#### Attributes and Cookies
Both arguments must adhere to the following format:
```
LINUX:
-c '{"PHPSESSID":"randomid"}'
-a '{"id":"name_form"}'

WINDOWS (quote escaping):
-c '{\"PHPSESSID\":\"randomid\"}'
-a '{\"id\":\"name_form\"}'
```
This is due to the strict parsing rules of the `json` library in python.