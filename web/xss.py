#!/bin/bash
import requests, json, os, re
from bs4 import BeautifulSoup
from optparse import OptionParser


# Help
def usage():
    print("""
        Usage: xss.py  -u [wesbite] -a [JSON list of attributes] -n [name of input] -f [payload_file]
        
        REQUIRED:
        -u or --url
        -f or --file
        -n or --name
        -a or --attrs

        OPTIONAL:
        -c or --cookies
        -v or --verbose
    """)
    exit(-1)

# Command line argument parser
def parse_args():
    parser = OptionParser()
    parser.set_conflict_handler("resolve")
    parser.add_option("-u", "--url",dest="url")
    parser.add_option("-c", "--cookies",dest="cookies")
    parser.add_option("-n", "--name",dest="input_name")
    parser.add_option("-f", "--file",dest="payload_file")
    parser.add_option("-a", "--attrs",dest="attributes")

    parser.add_option("-h", "--help", dest="help", action="store_true")
    parser.add_option("-v", "--verbose", dest="verbose", action="store_true")
    (options, args) = parser.parse_args()

    # Argument check
    if options.url and options.attributes and options.attributes and options.payload_file:
        if os.path.isfile(options.payload_file) == False:
            print(f"[!] {options.payload_file} doesn't exist")
            exit(-1)
        return options
    else:
        usage()

# Load JSON based value with error checking
def load_json_based(json_value):
    try:
        value = json.loads(json_value)
    except TypeError:
        value = {}
    return value

    


# Queries and parses site, sends requests with payloads, validates them
class Req():
    def __init__(self,OPTIONS):
        self.options = OPTIONS
        self.url = OPTIONS.url
        self.input_name = OPTIONS.input_name
        self.cookies = load_json_based(OPTIONS.cookies)
        self.attributes = load_json_based(OPTIONS.attributes)
        self.verbose = OPTIONS.verbose
        self.url_pattern = re.compile(r"https?://\S+")
        self.inputs = {}
        self.found = []
        self.forms = None
        self.method = None
        self.action_url = None
        self.last_req = None
        self.payload = None

    # GET and parse request
    def get(self):
        get = requests.get(self.url,cookies=self.cookies)
        if get.status_code == 200:
            self.forms = BeautifulSoup(get.content,"html.parser").find("form",attrs=self.attributes)
        else: 
            print(f"\n[!] {self.url} is down")
            exit(-1)
    
    # Set all inputs
    def set_input(self,payload):
        # Set basic variables
        self.payload = payload
        try:
            self.method = "GET" if self.forms.attrs.get("method") == None else self.forms.attrs.get("method").upper() 
            self.action_url = self.forms.attrs.get("action") if self.forms.attrs.get("action") else self.url
        except AttributeError:
            print(f"[!] Form with the following attributes cannot be found -- {self.options.attributes}")
            exit(-1)
        
        # Regex check
        match = self.url_pattern.search(self.action_url)
        self.action_url = self.action_url if match else self.url+self.action_url

        # Add value to specified input tag and load all others as is
        for input_tag in self.forms.find_all("input"):
            try:
                if input_tag["name"] == self.input_name:
                    self.inputs[input_tag["name"]] = payload
                else:
                    self.inputs[input_tag["name"]] = input_tag["value"]
            except KeyError:
                continue

    # Submit input
    def submit(self):
        if self.method == "POST":
            self.last_req = requests.post(self.action_url,data=self.inputs,cookies=self.cookies)
        elif self.method == "GET":
            self.last_req = requests.get(self.action_url,data=self.inputs,cookies=self.cookies)
        else:
            print(f"[!] Invalid method type: {self.method}")
            return

    # Check for XSS presence
    def validate_xss(self):
        if self.payload in self.last_req.text:
            self.found.append(self.payload)
            print(f"[*] {self.payload}")
        elif self.verbose:
            print(f"[-] {self.payload}")


    # Log all the payloads that work
    def log_working(self):
        print("\n========= Working Payloads =========")
        for p in self.found:
            print(p)



# Start the program
def start():
    # Arguments
    OPTIONS = parse_args()

    print(f"""
    __   __ _____ _____   _____ _               _             
    \ \ / //  ___/  ___| /  __ \ |             | |            
     \ V / \ `--.\ `--.  | /  \/ |__   ___  ___| | _____ _ __ 
     /   \  `--. \`--. \ | |   | '_ \ / _ \/ __| |/ / _ \ '__|
    / /^\ \/\__/ /\__/ / | \__/\ | | |  __/ (__|   <  __/ |   
    \/   \/\____/\____/   \____/_| |_|\___|\___|_|\_\___|_|   
                                                            
    XSS checker 1.0       

    """)
    print(f"[*] Running on {OPTIONS.url}\n")

    # Open payload file
    with open(OPTIONS.payload_file,"r") as f:
        file = f.readlines()
    
    # Run checker
    xss_checker = Req(OPTIONS)
    for url in file:
        xss_checker.get()
        xss_checker.set_input(url.replace("\n",""))
        xss_checker.submit()
        xss_checker.validate_xss()
    xss_checker.log_working()


# Driver
if __name__ == "__main__":
    start()