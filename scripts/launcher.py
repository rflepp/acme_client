import subprocess
import sys
import requests
import shlex
from pathlib import Path

# Get config data
j = requests.get(sys.argv[1]).json()
# Configure params
revoke = ' --revoke' if j['revoke'] else ''
# Create command
cmd = f"{j['challenge_type']} --dir {j['dir']} --record {j['record']} {' '.join(['--domain ' + d for d in j['domains']])} {revoke}"
dir_path = Path(__file__).absolute()
script = dir_path.parent.parent / "project/run"
cmd = f"timeout -k 1m 1m {script} {cmd}"
print("Going to run:", cmd)
p = subprocess.run(shlex.split(cmd))
