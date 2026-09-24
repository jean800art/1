"""Install the built addon into the next unused patch slot without overwriting."""
import hashlib
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).parent
GAME = ROOT.parents[1]
DATA = GAME / 'data'
PACKAGE = ROOT / 'build/ATE-HealthAmmo-3000-300.zip'
TOOLS = Path('C:/Users/27198/.codex/skills/hd2-lua-mod/tools')
sys.path.insert(0, str(TOOLS))
import hd2_archive

EXPECTED_EXE_SHA256 = 'D8E23968D1412B07E06785321727D63EDF74E711214D6F6ADEB3BFCA95CA6827'
PREFIX = '9ba626afa44a3aa3.patch_'

def main():
    assert hashlib.sha256((GAME / 'bin/helldivers2.exe').read_bytes()).hexdigest().upper() == EXPECTED_EXE_SHA256
    with zipfile.ZipFile(PACKAGE) as z:
        archive = z.read('Addon/' + hd2_archive.ARCHIVE_NAME)
    parsed = hd2_archive.parse(archive)
    assert parsed['count'] == 1
    entry = parsed['entries'][0]
    assert entry['name'] == hd2_archive.resource_hash('mods/lequla/ate_health_ammo')
    assert entry['version'] == 2 and b'new=3000' in entry['body'] and b'new=300' in entry['body']

    slots = []
    for path in DATA.glob(PREFIX + '*'):
        match = re.fullmatch(re.escape(PREFIX) + r'(\d+)', path.name)
        if match:
            slots.append(int(match.group(1)))
    slot = max(slots, default=-1) + 1
    targets = [DATA / f'{PREFIX}{slot}', DATA / f'{PREFIX}{slot}.stream', DATA / f'{PREFIX}{slot}.gpu_resources']
    assert all(not p.exists() for p in targets), 'next patch slot already exists; refusing overwrite'

    if __import__('subprocess').run(['powershell.exe','-NoProfile','-Command',
        "if (Get-Process -Name helldivers2 -ErrorAction SilentlyContinue) { exit 1 }"],
        check=False).returncode != 0:
        raise RuntimeError('Helldivers 2 is running; refusing install during active session')

    created = []
    try:
        for path, data in ((targets[0], archive), (targets[1], b''), (targets[2], b'')):
            with path.open('xb') as f:
                f.write(data)
            created.append(path)
    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    print('Installed patch slot:', slot)
    print('Patch SHA256:', hashlib.sha256(targets[0].read_bytes()).hexdigest().upper())
    print('Addon resource:', entry['name'])

if __name__ == '__main__':
    main()
