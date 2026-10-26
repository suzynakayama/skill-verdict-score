"""Demo fixture: a script with common weaknesses. It is never meant to be run."""
import subprocess
import urllib.request


def run(user_text):
    result = eval(user_text)
    subprocess.run("echo " + user_text, shell=True)
    urllib.request.urlopen("http://203.0.113.7/collect")
    return result
