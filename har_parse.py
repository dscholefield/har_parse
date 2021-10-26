#! /usr/bin/python3 

#
# parse.py - a tool for parsing, and comparing, JS file includes in HAR file contents
# D Scholefield. May 2020
#
# NOTE: use chrome .har files for maximum compatibility
#


import simplejson       # JSON parse library
import sys              # basic system calls 
import hashlib          # calculate MD5 hashes
import pprint           # pretty print
import colorama         # I want colour output!
import re               # regular expression library
import datetime         # format dates and time

# set debug mode, set to '1' if things are not going well!
debug = 0

# set whether external JS should be reported (usually you want this)
external = 1

# record lines to write to log on exit - NOTE: this is a global VAR, not nice
# we record the current time as the log timestamp so different log entries are connected
# with the time of script execution
log_lines = []
log_timestamp = datetime.datetime.now().strftime("[%d %b %Y, %H:%M] ")

# the summary log file will contain only whether changes or not have been detected
summary_log_string = log_timestamp

# we will save logs locally but you can change that here
# would be worth extracting to a config file?
log_filename = "harparse_log.txt"
summary_filename = "harparse_summary.txt"

# globals for ANSI color changes and initialise ANSI output
colorama.init()
RED = '\033[31m'   # mode 31 = red forground
GREEN = '\033[32m' # mode 32 = green foreground
RESET = '\033[0m'  # mode 0  = reset

# define a function to add to the log_lines in case
# we want to write the log file entries, this makes the
# log lines consistant in case of future searching etc.
def writeLog(new_line):
    log_lines.append(log_timestamp + new_line)

# function getJS will process .har file and return a dictionary mapping
# JS file URLs to {size, hash, content} records (as dicts)

def getJS(outerDict, debug):
    
    # create empty retrun dictionary for file details and new or changed JSFile
    JSFiles = {}
    file_details = {}

    file_details['title'] = outerDict['log']['pages'][0]['title']
    file_details['startedDateTime'] = outerDict['log']['pages'][0]['startedDateTime']

     # the domain needs to be detected so we need a Regex
    domain = re.compile('^(https://[^/]+)', re.IGNORECASE)
    page_domain = ""
    find_domain = re.match(domain, file_details['title'])
    if find_domain:
        page_domain = find_domain.group(1)
        print ("Page domain is " + page_domain)


    all_entries_array = outerDict['log']['entries']
    for entry in all_entries_array:
        # we will need to calculate hashes, note that MD5 is not a secure
        # hash and we are using it for change detection not signing etc.
        m = hashlib.md5()
        
        url = entry['request']['url']
        # we need to remove the query string from any URL
        # because they are often extemely long and reduce readability
        url = re.sub('\?.+$', '[qstring redacted]', url)

        # check for external vs internal domain
        if url.find(page_domain):
            # print (url + " is external")
            pass
        else:
            # print (url + " is internal")
            # we have an internal JS path so ignore the version number
            # if this is a Magento system, other content platforms
            # can be dealt with in a similar manner but if used 
            # regularly we should problem extract this to a config file
            url = re.sub('/version\d+/', '/version9999999999/',url)
            # for Demandware the version directory is slightly different
            url = re.sub('/v\d+/', '/v9999999999/',url) 

        # check response headers for JavaScript and only process those entries
        # record hash of content, size, and original (unhashed) content
        
        for header in entry['response']['headers']:
            # print ("Check url: " + url + "Found name: " + header['name'] + "and value: " + header['value'])
            if header['name'].lower() == 'content-type':
                if "javascript" in header['value']:
                    # ok, so we know it's JavaScript, let's record whether
                    # it's external so we can report if required
                   
                    if debug:
                        print ("Found name: " + header['name'] + "and value: " + header['value'])
                    if debug:
                        print ("Javascript Artifact found: " + url)
                   
                    if not 'text' in entry['response']['content'].keys():
                        print ("Anomoly ignored: no text content in " + url)
                        entry['response']['content']['text'] = "ADDED TEXT TO ANOMOLY"
                    content_to_hash = entry['response']['content']['text'].encode('utf-8')
                    m.update(content_to_hash)
                    if debug:
                        print ("\tsize: " + str(entry['response']['content']['size']) + " hash: " + m.hexdigest())
                    # build record for this file URL
                    JSFiles[url] = {}
                    JSFiles[url]['size']=entry['response']['content']['size']
                    JSFiles[url]['hash']=m.hexdigest()
                    # JSFiles[url]['text']=entry['response']['content']['text']
                    JSFiles[url]['text']="redacted"

                    # we will look for a referer too
                    JSFiles[url]['referer']=''
                    for request_header in entry['request']['headers']:
                        if request_header['name'].lower() == 'referer':
                            # print ("Found referer for %s is %s" % (url, request_header['value']))
                            JSFiles[url]['referer']=re.sub('\?.+$', '[qstring redacted]', request_header['value'])
                            # print ("Made referer for {0} as {1}".format(url, JSFiles[url]['referer']))

    
    return {'JSFiles' : JSFiles, 'fileDetails' : file_details}


# function readHAR will read a .har file and parse the contents into a dictonary

def readHAR(filename):
    outer_dict = {}
   
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            outer_dict = simplejson.load(f)
    except simplejson.errors.JSONDecodeError:
        print("\nThe file %s does not appear to be valid JSON.\nSometimes Chrome doesn't save the .har file properly. \
            \nSave the file again and retry!" % filename)
        sys.exit("Could not continue. Stopping.")

    return outer_dict


# function compareJS will return a dictionary with the
# following keys 
# 'newJS' (a dictionary mapping URLs to '1')
# 'hashDifferentJS ('a dictionary mapping URLs to dictionary
#   values {baseline,toCompare} with hashes)

def compareJS(baseDict, compDict):
    # make return data structure
    differences = {'newJS' : {}, 'hashDifferentJS' : {}}

    # first check for new JS files
    for key in compDict:
        if not key in baseDict:
            differences['newJS'][key]=1
        else:
            # not new so there must be a hash in both har files
            # we will compare the hashes
            if baseDict[key]['hash'] != compDict[key]['hash']:
                differences['hashDifferentJS'][key] = \
                    {'baseline' : baseDict[key]['hash'], 'compare' : compDict[key]['hash']}

    return differences


# function pTitle will print a simple title for the function

def pTitle():
    print ("")
    print ("**************************************")
    print ("\tJavaScript Change Check")
    print ("\tVer: 1.0, D Scholefield. May 2020")
    print ("**************************************")
    print ("")
    return None 

pTitle()


# get the .har file as a dictionary
print ("Reading baseline HAR...")
baselineDict = readHAR(sys.argv[1])


writeLog("Basline HAR: " + sys.argv[1])
print ("Reading new HAR...")
toCompareDict = readHAR(sys.argv[2])
writeLog("New HAR: " + sys.argv[2])

# parse the dictionaries
print ("Parsing baseline HAR...")
baselineFilesFoundDetails = getJS(baselineDict,debug)
print ("Parsing new HAR...")
compareFilesFoundDetails = getJS(toCompareDict,debug)

# isolate just he JavaScript information ready for comparison
baselineFilesFound = baselineFilesFoundDetails['JSFiles']
compareFilesFound = compareFilesFoundDetails['JSFiles']

# now we have both parsings we can compare them
print ("Comparing HARS...")
foundDifferences = compareJS(baselineFilesFound, compareFilesFound)

# finally, report the differences (or otherwise)


print ("Baseline filename: " + sys.argv[1])
print ("\tPage title:\t" + baselineFilesFoundDetails['fileDetails']['title'])
writeLog("Page title: " + baselineFilesFoundDetails['fileDetails']['title'])
print ("\tHAR creation:\t" + baselineFilesFoundDetails['fileDetails']['startedDateTime'])
writeLog("\tHAR creation:\t" + baselineFilesFoundDetails['fileDetails']['startedDateTime'])
print ("\tJS Files Found:\t" + str(len(baselineFilesFound)))
writeLog("\tJS Files Found:\t" + str(len(baselineFilesFound)))

print ("New filename: " + sys.argv[2])
print ("\tPage title:\t" + compareFilesFoundDetails['fileDetails']['title'])
writeLog("\tPage title:\t" + compareFilesFoundDetails['fileDetails']['title'])
print ("\tHAR creation:\t" + compareFilesFoundDetails['fileDetails']['startedDateTime'])
writeLog("\tHAR creation:\t" + compareFilesFoundDetails['fileDetails']['startedDateTime'])
print ("\tJS Files Found:\t" + str(len(compareFilesFound)))
writeLog("\tJS Files Found:\t" + str(len(compareFilesFound)))
print ("")

summary_log_string += baselineFilesFoundDetails['fileDetails']['title'] + ", " + sys.argv[1] \
    + ", " + sys.argv[2] + ", "
if not bool(foundDifferences['newJS']) and not bool(foundDifferences['hashDifferentJS']):
    print (GREEN)
    print (u'\u221A' + RESET + " All clear - no changes found")
    writeLog(" All clear - no changes found")
    summary_log_string += "no changes"
else:
    print (RED)
    print (u'\u2573' + RESET + " Warning - changes found!")
    writeLog(" Warning - changes found!")
    summary_log_string += "CHANGES"
print("")

if not bool(foundDifferences['newJS']):
    print ("No new JS files found")
    writeLog("No new JS files found")
else:
    print (str(len(foundDifferences['newJS'])) + " new JavaScript files found")
    writeLog(" new JavaScript files found")
    for JSfilename in foundDifferences['newJS'].keys():
        print ("\t" + JSfilename, end='')
        if compareFilesFound[JSfilename]['referer'] != '':
            print (" [Referer:{0}]".format(compareFilesFound[JSfilename]['referer']))
        else:
            print("\n")
        writeLog(JSfilename)

if not bool(foundDifferences['hashDifferentJS']):
    print ("No changes in JS found")
    writeLog("No changes in JS found")
else:
    print (str(len(foundDifferences['hashDifferentJS'])) + " changed JavaScript files found")
    writeLog(" changed JavaScript files found")
    for JSfilename in foundDifferences['hashDifferentJS'].keys():
        print ("\t" + JSfilename, end='')
        if compareFilesFound[JSfilename]['referer'] != '':
            print (" [Referer:{0}]".format(compareFilesFound[JSfilename]['referer']))
        else:
            print("\n")
        writeLog("baseline hash: " \
            + foundDifferences['hashDifferentJS'][JSfilename]['baseline'] \
            + ",new hash: " \
            + foundDifferences['hashDifferentJS'][JSfilename]['compare']
        )

# write the detailed logfile
my_logfile = open(log_filename, "a+")
for line in log_lines:
    my_logfile.write(line + "\n")
my_logfile.close()

# write the summary logfile
my_summary_logfile = open(summary_filename, "a+")
my_summary_logfile.write(summary_log_string + "\n")
my_summary_logfile.close()


exit




