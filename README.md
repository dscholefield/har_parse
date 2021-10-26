# har_parse
Compares saved browser .har file against pre-saved baseline and identifies changes in embedded JavaScript scripts and files

Background
It is important to be able to detect unauthorised JavaScript changes to certain critical web pages as part of a regular security assurance program especially for web pages that process sensitive personal information or payment information. Although authorised JavaScript changes can be reviewed as part of a git repository pull request (for example), or using SAST tools in the CD/CI pipeline, modern malware is often injected into a live service without the knowledge of the website owner. One possible way to detect these changes are to download the current .har file (https://en.wikipedia.org/wiki/HAR_(file_format)) and examine the JavaScript that is both inline and sourced from internal and external URLs. In fact, this is one of the most comprehensive ways of detecting JavaScript changes as the .har file will record dynamically generated source URLs at the time of page rendering (though not necessarily during interaction with the DOM which can only then be detected by examining the network interactions through a proxy or similar).

The har_parse script is a simple 'parse and compare' tool that requires the user to download and manually check a baseline .har file which has been saved from a browsing session against a newly downloaded .har file of that page. It detects the JavaScript includes in the page and in addition to highlighting newly imported JavaScript, compares the MD5 hashes of the scripts so as to detect changes in existing includes. A short report is created and the comparison effort and results are appended to summary and detailed log files.

Usage:
```
python3 har_parse.py <baseline .har file> <new .har file>
```
