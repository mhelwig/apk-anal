#!/usr/bin/python
#-*- coding:UTF-8 -*-

#
#                          apk-anal.py
#                     Android APK Analyzer
#     by Michael Helwig (@c0dmtr1x / www.codemetrix.net)
#
#
#      Basic APK analysis based on radare2 and others
#
#       Requires:
#       - apktool (https://ibotpeaches.github.io/Apktool/)
#       - radare2 (https://radare.org - use latest from Git)
#       - python-modules: filemagic, r2pipe
#       - grep with -E option
#
#      Optional:
#       - APKiD: https://github.com/rednaga/APKiD
#
#      Adjust the path to apktool below                  .
#
#
#      License: LGPLv3
#

from __future__ import print_function
import r2pipe
import sys,os,subprocess
import shutil,itertools,argparse,zipfile
import magic
from xml.dom.minidom import parseString

# Path to apktool
apktool=""

# Checks for strings, imports, methods and symbols
apkchecks =  {"strings":[".apk",".dex"]}
rootchecks=  {"strings":["bin/su", "sudo", "superuser"]}
apichecks=   {"imports":["nfc", "PackageInstaller", "bluetooth","install","PackageManager","Datagram", "fingerprint"], "methods":["fingerprint","bluetooth","install","package"], "symbols":["fingerprint","bluetooth","install","package"]}
smschecks =  {"imports":["sms","telephony"],"methods":["sms","telephony","getDeviceId", "getSimOperator", "getSimCountry", "getImei"],"symbols":["sms","telephony","getDeviceId", "getSimOperator", "getSimCountry", "getImei"]}
locationchecks = {"imports":["GoogleApiClient","FusedLocationProvider","setMockLocation"],"methods":["getLastLocation","getLocationAvailability","requestLocationUpdates","setMockLocation"],"symbols":["getLastLocation","getLocationAvailability","requestLocationUpdates"]}
netchecks =  {"imports":["http","socket","tcp","udp"],"strings":["client","socket","connect","url","uri"], "methods":["connect","send","tcp","udp"], "symbols":["connect","send","tcp","udp"]}
urlchecks =  {"strings":["http:","https:","ftp:","rtsp:"]}
filechecks = {"imports":["java/io/File"],"symbols":["openFileOutputStream","getFilesDir", "getCacheDir","deleteFile", "getExternalStorageState", "isWritable", "setWritable"],"strings":["file:","/tmp/","/data/"]}
cryptochecks = {"imports":["crypt","keystore","cipher"],"methods":["crypt","cipher","keystore"],"symbols":["crypt","cipher","keystore"]}
httpschecks = {"imports":["javax/net/ssl"]}
nativechecks ={"strings":["loadLibrary"],"methods":["loadLibrary"],"symbols":["loadLibrary"]}
camerachecks = {"imports":["android/hardware/Camera","android/hardware/Camera2","camera"],"methods":["camera","takePicture"],"symbols":["camera","takePicture"]}
audiochecks = {"imports":["android/media/MediaRecorder","MediaRecorder"]}
emulatorchecks = {"imports":["EmulatorDetector"], "strings":["google_sdk","init.goldfish.rc"], "methods":["isEmulator"]}
otherchecks = {"strings":["api_key","password","pass","admin","secret","encrypt","decrypt"],"methods":["password","pass","admin","secret","encrypt","decrypt"]}

# Filter (only for urls in assets at the moment)
filter_urls = ["http://schemas.android.com/"]

# Radare2 wrapper functions
def r2_check(strings,r2p,r2cmd):
    cmd = r2cmd + "~+" + ",".join(strings)
    results = r2p.cmd(cmd)
    return results

def r2_check_strings(strings,myr2pipe,message=None):
    return r2_check(strings,r2p,"izzq")

def r2_check_classes_and_methods(strings,r2p,message=None):
    return r2_check(strings,r2p,"icq")

def r2_check_imports(strings,r2p,message=None):
    return r2_check(strings,r2p,"iiq")

def r2_check_symbols(strings,r2p,message=None):
    return r2_check(strings,r2p,"isq")

def r2_cmd(cmd, r2p):
    return r2p.cmd(cmd)

def r2_pd_xrefs(address,r2p):
    cmd = "pd 1 @  " + address + "~XREF"
    result = r2p.cmd(cmd)
    return result

# Do searches with radare2
def analyse(checks,r2p):
    result = {}
    if "strings" in checks:
        result["strings"] = r2_check_strings(checks["strings"],r2p)
    if "methods" in checks:
        result["methods"] = r2_check_classes_and_methods(checks["methods"],r2p)
    if "imports" in checks:
        result["imports"] = r2_check_imports(checks["imports"],r2p)
    if "symbols" in checks:
        result["symbols"] = r2_check_symbols(checks["symbols"],r2p)
    return result

# Try to find xrefs
def r2_get_xrefs(r2_result,result_type,r2p):
    if "vaddr=" in r2_result:
        address = (r2_result.split(" ")[0]).split("=")[1]
    else:
        address = r2_result.split(" ")[0]
    if result_type == "strings":
        xrefs = r2_pd_xrefs(address,r2p)
        # Sometimes string results seem to be shifted by 1 byte. There's probably a beter solution to this...
        if not xrefs:
            xrefs = r2_pd_xrefs(address + "-1",r2p)
        return xrefs
    else:
        return r2_pd_xrefs(address,r2p)

# Locate dex files
def get_dex_files(directory):
    list=[]
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".dex"):
                list.append(os.path.join(root,file))
    return list

# Print permission from Manifest
def print_manifest(manifestpath):
    with open(manifestpath,'r') as f:
        data = f.read()
        dom = parseString(data)
        manifest_nodes = dom.getElementsByTagName('manifest')
        activity_nodes = dom.getElementsByTagName('activity')
        service_nodes = dom.getElementsByTagName('service')
        receiver_nodes = dom.getElementsByTagName('receiver')

        for node in manifest_nodes:
            print("[*] Package: " + node.getAttribute("package"))

        print("\n[*] Activitives:")
        for node in activity_nodes:
            print(node.getAttribute("android:name"))

        print("\n[*] Services:")
        for node in service_nodes:
            print(node.getAttribute("android:name"))

        print("\n[*] Receivers:")
        for node in receiver_nodes:
            print(node.getAttribute("android:name"))
            intent_filters = node.getElementsByTagName('intent-filter')
            if len(intent_filters) > 0:
               for filter_node in intent_filters:
                    action_nodes = filter_node.getElementsByTagName('action')
                    for action_node in action_nodes:
                         print(" -> " + action_node.getAttribute("android:name"))

        print("\n[*] Permissions requested: ")
        permission_nodes = dom.getElementsByTagName('uses-permission')
        for node in permission_nodes:
            print(node.toxml())

# Output with xrefs
def print_with_xrefs(r2_results,result_type,r2p):
    for result in r2_results.split("\n"):
        try:
            print(result)
        except UnicodeEncodeError:
            print(result.encode('ascii', 'ignore'))
        xrefs = r2_get_xrefs(result,result_type,r2p)
        if xrefs:
            for xref in xrefs.split("\n"):
                output = xref.lstrip()[1:].lstrip()
                if(output[0] == ';'):
                     output = output[2:]
                print(" -> " + output)

# Output analysis results
def print_results(analysis_results,messages,r2p):
    for key,result in analysis_results.iteritems():
        if len(result) > 0:
            print(messages["found"] % key)
            if key in ["strings","symbols","methods"]:
                print_with_xrefs(result,key,r2p)
            else:
                print(result)
        else:
            print(messages["not_found"] % key)

    return

# Argparse
parser = argparse.ArgumentParser()
parser.add_argument('--output', '-o', help='output directory')
parser.add_argument('--dex' , '-d', help='dex file to analyse (skips extraction and disassembly of apk)', action='store_true')
parser.add_argument('--apktool', help='Path to apktool jar file')
parser.add_argument('--skip-extraction',  help='skip decompilation & extraction. Assumes you already have something extracted to output-dir',action='store_true')
parser.add_argument('--skip-assets',  help='skip asset listing and filetype detection',action='store_true')
parser.add_argument('--extended', help='Do extended radare2 analysis. Try to find XREFS. This might take some time.', action='store_true')
parser.add_argument('--cleanup', help='Delete extracted files after completion. WARNING: Deletes contents of output directory', action='store_true')
parser.add_argument('--cleanup-before', help='Cleanup before extraction. WARNING: Deletes contents of output directory', action='store_true')
parser.add_argument('apkfile', help="apk file to analyse", nargs='?')
args = parser.parse_args()

apkfile = args.apkfile
skip_extraction = args.skip_extraction or args.dex
skip_disassembly = args.skip_extraction or args.dex

if not skip_extraction and apkfile is None:
    print("[!] No file given. Please provide an apkfile (or dexfile with -d option). Use -h for help.")
    exit(1)

if not apktool:
    apktool = args.apktool

if not apktool or not os.path.isfile(apktool):
    print("[!] Apktool not found. Please adjust path in script or provide it with --apktool")
    exit(1)

# Setting paths
extract_dir = None
working_dir = "apk-extracted"

if args.output:
    extract_dir = args.output
else:
    extract_dir = os.getcwd()+ '/' + working_dir

zip_dir = extract_dir + "/zip"
asset_dir = extract_dir + "/zip/assets"
smali_dir = extract_dir + "/smali"

if not args.skip_extraction and os.path.isdir(extract_dir) and os.listdir(extract_dir) != [] and not args.cleanup_before and not args.dex:
    print("\n[!] " + "Output dir is not empty. Use --cleanup-before to empty output directory.")
    sys.exit(1)


# Header

print("\n### APK-Anal - Android APK Analyzer (by @c0dmtr1x) ###")

# Cleanup before
if args.cleanup_before:
    print("\n[*] Cleaning up working_dir...")
    if(os.path.isdir(extract_dir)):
        shutil.rmtree(extract_dir + "/")

# Extracting APK
print("\n[*] Extracting to: " + extract_dir)

if not skip_extraction:
    print("[*] Extracting APK file as zip")
    if not os.path.isfile(apkfile):
        sys.exit("APK file not found.")
    zip_ref = zipfile.ZipFile(apkfile, 'r')
    zip_ref.extractall(extract_dir + "/zip")
    zip_ref.close()

if not skip_disassembly:
    print("[*] Disassembling apkfile with apktool:")
    output = subprocess.check_output(["java", "-jar", apktool, "d", apkfile, "-o", smali_dir])
    print(output)

if not args.dex:
    dexlist = get_dex_files(extract_dir + "/zip/")
    if os.path.isfile(smali_dir + "/AndroidManifest.xml"):
       print_manifest(smali_dir + "/AndroidManifest.xml")
    else:
        print("\n[!] Apktool not found, skipping smali extraction and manifest analysis...")
else:
    if args.apkfile and os.path.isfile(args.apkfile):
        dexlist = [args.apkfile]
    else:
        print("[!] Input file not found. Please provide the correct filepath.")
        sys.exit(1)

print("\n[*] Found " + str(len(dexlist)) + " dexfiles:")
print(dexlist)

# Dex analysis
for dexfile in dexlist:

    print("\n[***] Analysing " + dexfile + " [***]")
    print("\n[*] Running APKiD ")

    try:
        output = subprocess.check_output(["apkid", dexfile])
        print(output)
        if not "compiler : dx" in output:
            print("[*] Notice: APKiD detected non-standard dex compiler (e.g. dexlib) - This might indicate malicious / repackaged APKs.")
        if "anti_vm" in output:
            print("[*] Notice: APKiD found possible emulator detection (anti-vm).")
        if "anti_disassembly" in output:
            print("[*] Notice: APKiD found anti disassembly measures (anti-disassembly).")
    except OSError as e:
        if e.errno == os.errno.ENOENT:
            print("[*] APKiD not found. Skipping.")
        else:
            raise

    # Open dex with radare2
    print("\n[*] Opening dexfile with radare2...")
    r2p=r2pipe.open(dexfile)

    # Analyse with radare2
    if args.extended:
        print("\n[*] Analyzing with radare2. This might take some time... ")
        r2_cmd("aad;aan;aas;",r2p)

    # Root detection check
    rootresults = analyse(rootchecks,r2p)
    print_results(rootresults,{"found":"\n[*] Possible root detection found in %s:","not_found":"\n[*] No signs of root detection in %s"},r2p)

    # References to APKs and dex files
    apkresults = analyse(apkchecks,r2p)
    print_results(apkresults,{"found":"\n[*] References to apks or dexfiles found in %s:","not_found":"\n[*] No references to apks and dexfiles found in %s"},r2p)

    # Check for sms & telephony
    smsresults = analyse(smschecks,r2p)
    print_results(smsresults,{"found":"\n[*] SMS or telephony usage found in %s","not_found":"\n[*] No SMS or telephony usage found in %s"},r2p)

    # Check for location requests
    locationresults = analyse(locationchecks,r2p)
    print_results(locationresults,{"found":"\n[*] Location api / access found in %s","not_found":"\n[*] No location api / access found in %s"},r2p)

    # References to interesting apis
    apiresults = analyse(apichecks,r2p)
    print_results(apiresults,{"found":"\n[*] Interesting API references (nfc, bluetooth...) found %s:","not_found":"\n[*] No interesting API (nfc, bluetooth...) references found in %s"},r2p)

    # Check for urls
    urlresults = analyse(urlchecks,r2p)
    print_results(urlresults,{"found":"\n[*] Possible URLs found in %s","not_found":"\n[*] No URLs found in %s"},r2p)

    # Check for crypto:
    cryptoresults = analyse(cryptochecks,r2p)
    print_results(cryptoresults,{"found":"\n[*] Possible crypto stuff found in %s","not_found":"\n[*] No crypto stuff found in %s"},r2p)

    # Check for file access
    fileresults = analyse(filechecks,r2p)
    print_results(fileresults,{"found":"\n[*] Possible file access / references found in %s","not_found":"\n[*] No file access / references found in %s"},r2p)

    # Check for https
    httpsresults = analyse(httpschecks,r2p)
    print_results(httpsresults,{"found":"\n[*] Possible https / certificate references found in %s","not_found":"\n[*] No https / certificate references found in %s"},r2p)

    # Check for communication and clients
    netresults = analyse(netchecks,r2p)
    print_results(netresults,{"found":"\n[*] Possible client / communication keywords found in %s","not_found":"\n[*] No client / communication keywords found in %s"},r2p)

    # Check for native library loading
    nativeresults = analyse(nativechecks,r2p)
    print_results(nativeresults,{"found":"\n[*] Possible signs of native library loading found in %s","not_found":"\n[*] No signs of native library loading found in %s"},r2p)

    # Check for camera imports
    cameraresults = analyse(camerachecks,r2p)
    print_results(cameraresults,{"found":"\n[*] Possible camera api calls found in %s","not_found":"\n[*] No camera api references found in %s"},r2p)

    # Check for audio recording imports
    audioresults = analyse(audiochecks,r2p)
    print_results(audioresults,{"found":"\n[*] Possible audio recording found in %s","not_found":"\n[*] No signs of audio recording found in %s"},r2p)

    # Check for emulator / vm detection
    emulatorresults = analyse(emulatorchecks,r2p)
    print_results(emulatorresults,{"found":"\n[*] Signs of emulator detection found in %s","not_found":"\n[*] No signs of emulator detection found in %s"},r2p)

    # Check for passwords and other interesting strings
    otherresults = analyse(otherchecks,r2p)
    print_results(otherresults,{"found":"\n[*] Further interesting stuff found in %s","not_found":"\n[*] No more interesting things found in %s"},r2p)

print("\n[***] End of dex analysis [***]")

if args.dex:
    print("\n[*] Done")
    sys.exit(0)

# Check for native libraries (folders)
lib_dir = extract_dir + "/zip/" + "lib"
if os.path.isdir(lib_dir):
    print("\n[*] Native libraries found:")
    for root, dirs, files in os.walk(lib_dir):
        for file in files:
            print(os.path.join(root,file))
else:
    print("\n[*] No native libraries found")

# Output assets
if not args.skip_assets:
    if os.path.isdir(asset_dir):
        print("\n[*] Assets found:")
        with magic.Magic() as m:
            for root, dirs, files in os.walk(asset_dir):
                for file in files:
                    filetype = m.id_filename(os.path.join(root,file))
                    print(os.path.join(root,file) + " - " + filetype)
    else:
        print("\n[*] No assets found")


print("\n[*] Looking for interesting filetypes and files:")
for root, dirs, files in os.walk(extract_dir + "/zip/"):
    for file in files:
        interesting_types = ["certificate", "serialize", "json", "database"]
        interesting_exts = ["jks","apk","crt","cert","pem","rsa"]
        filepath = os.path.join(root,file)

        with magic.Magic() as m:
            filetype = m.id_filename(filepath)
        if (any(x in filetype.lower() for x in interesting_types) or filetype == "data"):
            print(" " + filepath + " - " + filetype)
        elif os.path.splitext(filepath) and len(os.path.splitext(filepath)) > 1:
            if any(x in os.path.splitext(filepath)[1].lower() for x in interesting_exts):
                print(" " + filepath + " - " + filetype)

# Looking for IPs
if os.path.isdir(zip_dir):
    print("\n[*] Looking for IPv4s in unzipped APK file")
    try:
        result = subprocess.check_output(["grep","-arnoE","[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", zip_dir])
        print(result)
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            print(" -> No results found")
        else:
            print(" [!] Error executing grep")
    if os.path.isdir(smali_dir + "/res"):
        print("\n[*] Looking for IPv4s in extracted ressources")
        try:
            result = subprocess.check_output(["grep","-arnoE","[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", smali_dir + "/res"])
            print(result)
        except subprocess.CalledProcessError as e:
            if e.returncode == 1:
                print(" -> No results found")
            else:
                print(" [!] Error executing grep")

# Looking for URLs in assets
if os.path.isdir(zip_dir):
    print("\n[*] Looking for URLs in unzipped APK file")
    try:
        result = subprocess.check_output(["grep","-arnoE","(http|https|file|ftp)://[a-zA-Z0-9?/._=-]+" ,zip_dir])
        filtered = True
        for line in result.split("\n"):
            if not any(x in line for x in filter_urls) and line != "":
                print(line)
                filtered = False
        if filtered:
            print(" -> No interesting results found (filtered)")
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            print(" -> No results found")
        else:
            print(" [!] Error executing grep")
    if os.path.isdir(smali_dir + "/res"):
        print("\n[*] Looking for URLs in extracted ressources")
        try:
            result = subprocess.check_output(["grep","-arnoE","(http|https|file|ftp)://[a-zA-Z0-9?/._=-]+", smali_dir + "/res" ])
            filtered = True
            for line in result.split("\n"):
                if not any(x in line for x in filter_urls) and line != "":
                    print(line)
                    filtered = False
            if filtered == True:
                print(" -> No interesting results found (filtered)")
        except subprocess.CalledProcessError as e:
            if e.returncode == 1:
                print(" -> No results found")
            else:
                print(" [!] Error executing grep")


# Looking for certificates
if os.path.isdir(zip_dir):
    print("\n[*] Looking for private / public key files")
    try:
        result = subprocess.check_output(["grep","-arnoE","(PRIVATE|PUBLIC) KEY", zip_dir])
        print(result)
    except subprocess.CalledProcessError as e:
        if e.returncode != 1:
            print(" [!] Error executing grep")
        else:
            print(" -> No results found")
# Cleanup
if args.cleanup:
    print("\n[*] Cleaning up ...")
    shutil.rmtree(extract_dir)

print("\n[*] Done")
