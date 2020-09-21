[![Build Status](https://travis-ci.org/rantanevich/MobilePASSER.svg?branch=python)](https://travis-ci.org/rantanevich/MobilePASSER)

MobilePASSER is a tool that generates OTP based on activation code from SafeNet MobilePASS.

SafeNet MobilePASS does not use time-based algorithm. It uses a counter which saves its state in the file. When we push "Generate Passcode" the couter retrieves last state from the file, incremets value, generates token and saves state into the file.

You can find more details in the article: [http://sbudella.altervista.org/blog/20180128-mobilepass.html](http://sbudella.altervista.org/blog/20180128-mobilepass.html)

Requirements
------------

You need Python 3.6.1 or later.

Installation
------------

Use the package manager `pip` to install MobilePASS.
```
pip install MobilePASS
```

Examples
--------

After first running `.mobilepass` file will be created in home directory. Next running will give you the next passcode and so on. You can omit any parameters now because Activation Code and other parameters are saved in the file.
```
$ mobilepass -k QVKYC-FM6KO-SY6F7-TR22
374844
$ mobilepass
124927
...
$ mobilepass
555522
```

If you want to save to another file you have to use key `-c` or `--config`. But you should use that key every running.
```
$ mobilepass -k QVKYC-FM6KO-SY6F7-TR22 -c /etc/mobilepass.cfg
374844
mobilepass -c /etc/mobilepass.cfg
124927
```

Usage
-----


```bash
$ mobilepass --help
usage: mobilepass [-h] [-c CONFIG] [-k KEY] [-i INDEX] [-p POLICY] [-u]

Generate OTP based on activation code from SafeNet MobilePASS

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        path to the configuration file
  -k KEY, --key KEY     activation code generated in SafeNet MobilePASS
  -i INDEX, --index INDEX
                        ordinal number of the one-time passcode
  -p POLICY, --policy POLICY
                        token policy string
  -u, --update          increse the index by 1 and save to config file
```

Activation code is only one requirement argument. You should take it from SafeNet MobilePASS ([Windows](https://www.microsoft.com/en-us/p/safenet-mobilepass/9nblggh10pdq?activetab=pivot:overviewtab)/[Android](https://play.google.com/store/apps/details?id=securecomputing.devices.android.controller)/[MacOS](https://apps.apple.com/us/app/mobilepass/id972648459?mt=12)) and register it in SafeNet Authentication Manager

The rest arguments have default values:
```
-i, --index  = 0
-p, --policy = none
-u, --update = true
-c, --config = $HOME/.mobilepass
```

Configuration
-------------

You can save parameters into the configuration file. Default path is `$HOME/.mobilepass`

Example content:
```
[MobilePASS]
ActivationCode  = QVKYC-FM6KO-SY6F7-TR22W
Policy          =
Index           = 0
AutoUpdateIndex = true
```
The section name `[MobilePASS]` is case-sensive, but options are not.
