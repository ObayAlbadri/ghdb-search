# ghdb-search
Query GHDB for dorks and save a clean response to a file.

# Usage

``` 
python3 ghdb-search.py --search 'mysql' --output  dorks.txt
or
python3 ghdb-search.py -s 'mysql' -c 1 -n 3 -ps 1 -o dorks.txt
```


Argument | Description
-------------- | ----------------
`-s` or `--search` | Search term
`-ps` or `--position-start` | Start at this position
`-n` or `--no-of-results` | Number of results to fetch
`-c` or  `--category-no` | Category number (from 1 to 14)                
`-o` or `--output` | Output file




### Categories
1.   Footholds
2.   Files Containing Usernames
3.   Sensitive Directories
4.   Web Server Detection
5.   Vulnerable Files
6.   Vulnerable Servers
7.   Error Messages
8.   Files Containing Juicy Info
9.   Files Containing Passwords
10.  Sensitive Online Shopping Info
11.  Network or Vulnerability Data
12.  Pages Containing Login Portals
13.  Various Online Devices
14.  Advisories and Vulnerabilities

## Requirements
* python3
* requests

## Notes
This tool is old -but working as of November 2020- and not maintained anymore. This tool is created for educational purpose only ,the creator assume no liability and is not responsible for any misuse or damage caused by this program. Only use legally.
