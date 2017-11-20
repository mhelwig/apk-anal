# apk-anal
Android APK analyzer based on radare2 and others.

# What does it do?
It's an static analys tool for APK files based on radare2, apktool and APKiD. It tries to quickly determine interesting features like 

* root detection
* emulator detection
* unusual files
* URLs, IPs
* interesting API access (camera, mic, bluetooth, nfc, location, fingerprint...)

etc. Under the hood, it uses radare2 to look for certain strings, methods, symbols and imports in the dex file(s). It also extracts the APK and disassembles it to smali files (using apktool) so you can continue your analysis afterwards.

When doing extended analysis (via `--extended` flag) APK-Anal tries to find cross references within the code to show you which methods access certain strings, files, urls etc. so you have a starting point for further analysis.

The script was more or less quickly hacked together and only tested with a handful of malware samples. Don't expect too much. You might get similar information using online services like "koodous". Still, it's useful for quick analysis on your local system.

This script was based on an article by @trufae on analysing APK files with radare2: https://www.nowsecure.com/blog/2016/11/21/android-malware-analysis-radare-triada-trojan/

# Why apk-anal?

Because of Radare2 (https://github.com/radare/radare2/tree/master/libr/anal).

# Requirements
                                            
- apktool (https://ibotpeaches.github.io/Apktool/)   
- radare2 (https://radare.org - use latest from Git) 
- python-modules: filemagic, r2pipe, argparse
- grep with -E option
- java in path
                                                            
Optional (but useful):                                             
- APKiD: https://github.com/rednaga/APKiD  

# Installation

Just download the apk-anal.py script. You have to install the requirements yourself.

You should be able to install the python requirements via the requirements.txt file:

```pip install -r requirements.txt```

# Usage

```
% python apk-anal.py -h
usage: apk-anal.py [-h] [--output OUTPUT] [--dex] [--apktool APKTOOL]
                   [--skip-extraction] [--skip-assets] [--extended]
                   [--cleanup] [--cleanup-before]
                   [apkfile]

positional arguments:
  apkfile               apk file to analyse

optional arguments:
  -h, --help            show this help message and exit
  --output OUTPUT, -o OUTPUT
                        output directory
  --dex, -d             dex file to analyse (skips extraction and disassembly
                        of apk)
  --apktool APKTOOL     Path to apktool jar file
  --skip-extraction     skip decompilation & extraction. Assumes you already
                        have something extracted to output-dir
  --skip-assets         skip asset listing and filetype detection
  --extended            Do extended radare2 analysis. Try to find XREFS. This
                        might take some time.
  --cleanup             Delete extracted files after completion. WARNING: Deletes content
                        of output directory.
  --cleanup-before      Cleanup before extraction. WARNING: Deletes content
                        of output directory.

```

# Examples

Analyse APK file:

```python apk-anal.py --apktool /opt/apktool_2.2.4.jar example.apk```

Analyse DEX file:

```python apk-anal.py --apktool /opt/apktool_2.2.4.jar -d example.dex```

Extended analysis with radare2 (which gives you XREFS):

```python apk-anal.py --extended --apktool /opt/apktool_2.2.4.jar example.apk```

[![asciicast](https://asciinema.org/a/146659.png)](https://asciinema.org/a/146659)

# Further development

Please let me know about issues and suggestions for improvements. Search terms can certainly be improved and adjusted.

Feel free to contact me on Twitter ([@c0dmtr1x](https://twitter.com/c0dmtr1x)) or via email (info@codemetrix.net).
