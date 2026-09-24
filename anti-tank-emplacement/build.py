"""Build an installable E/AT-12 health/ammunition addon."""
import hashlib
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).parent
GAME = ROOT.parents[1]
TOOLS = Path('C:/Users/27198/.codex/skills/hd2-lua-mod/tools')
sys.path.insert(0, str(TOOLS))
import build_addon
import hd2_archive

ENTRY = ROOT / 'ate_health_ammo.lua'
PACKAGE = ROOT / 'build/ATE-HealthAmmo-3000-300.zip'
GUID = 'bb8e22d9-5ea9-40b7-a85b-d71a035a76e2'
RESOURCE = 'mods/lequla/ate_health_ammo'

def main():
    source = ENTRY.read_bytes()
    assert source.startswith(b'-- HD2-Addon: mods/lequla/ate_health_ammo\n')
    assert len(source.splitlines()[0]) < 256
    assert b"new=3000" in source and b"new=300" in source
    assert b"D8E23968D1412B07E06785321727D63EDF74E711214D6F6ADEB3BFCA95CA6827" in source
    PACKAGE.parent.mkdir(exist_ok=True)
    _, archive = build_addon.build_package(RESOURCE, ENTRY, GUID, PACKAGE,
        'E/AT-12 Health 3000 Ammo 300')
    with zipfile.ZipFile(PACKAGE, 'a', compression=zipfile.ZIP_DEFLATED) as z:
        z.write(ROOT / 'PLAY.md', 'PLAY.md')
    with zipfile.ZipFile(PACKAGE) as z:
        assert z.testzip() is None
        assert json.loads(z.read('manifest.json'))['Guid'] == GUID
        parsed = hd2_archive.parse(archive)
        assert parsed['count'] == 1
        resource = parsed['entries'][0]
        assert resource['name'] == hd2_archive.resource_hash(RESOURCE)
        assert resource['version'] == 2 and resource['body'] == source
        assert z.read('Addon/' + hd2_archive.ARCHIVE_NAME) == archive
    report = {
        'game_executable_sha256': hashlib.sha256((GAME / 'bin/helldivers2.exe').read_bytes()).hexdigest().upper(),
        'resource': RESOURCE,
        'resource_hash': f"{hd2_archive.resource_hash(RESOURCE):016X}",
        'package_sha256': hashlib.sha256(PACKAGE.read_bytes()).hexdigest().upper(),
        'source_sha256': hashlib.sha256(source).hexdigest().upper(),
        'targets': {'health': {'from': 300, 'to': 3000}, 'magazine_capacity': {'from': 30, 'to': 300}},
        'unchanged': ['rate of fire', 'fire mode', 'magazine refill fields'],
        'validation': 'archive round-trip, manifest GUID, and entry source readback passed',
        'deployment': 'package only; not installed or runtime tested',
    }
    (ROOT / 'build/build-report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('Package:', PACKAGE)
    print('SHA256:', report['package_sha256'])

if __name__ == '__main__':
    main()
