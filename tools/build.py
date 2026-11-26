"""Build the current checkout independently from the original Codex workspace."""
import ast
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent
VERSION = (ROOT / 'VERSION').read_text().strip()
if not re.fullmatch(r'\d+\.\d+(?:\.\d+)?', VERSION):
    raise SystemExit('Invalid VERSION')
DIST = ROOT / 'dist'
DIST.mkdir(exist_ok=True)
FILES = ['class_manager.py', 'cm_core.py', 'cm_ui.py', 'credential_store.py',
         'test_cm.py', 'test_cm_extended.py', 'test_cm_ui.py', 'README-RU.txt',
         'requirements.txt', 'computers-example.csv', 'Start-CM.cmd', 'Start-CM.sh', 'Install-CM-Astra.sh',
         'docs/first-start.md']
with tempfile.TemporaryDirectory(prefix='cm-build-', dir=DIST) as temporary:
    stage = Path(temporary) / 'CM-Astra'
    stage.mkdir()
    for relative in FILES:
        source = ROOT / relative
        target = stage / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        if source.suffix == '.py':
            ast.parse(target.read_text(encoding='utf-8'), feature_version=(3, 9))
        if source.suffix == '.sh':
            target.chmod(0o755)
    (stage / 'computers.json').write_text('[]')
    (stage / 'key-catalog.json').write_text('{}')
    tests = ['test_cm.py', 'test_cm_extended.py']
    if '--ui-tests' in sys.argv:
        tests.append('test_cm_ui.py')
    results = []
    for test in tests:
        result = subprocess.run([sys.executable, '-B', str(stage / test)], capture_output=True, text=True)
        if result.returncode:
            raise SystemExit(result.stdout + result.stderr)
        results.append(result.stdout + result.stderr)
    (stage / 'TEST-RESULTS.txt').write_text('CM ' + VERSION + '\n' + '\n'.join(results)
        + '\nSSH/SFTP and vault APIs are fake; clock_settime is stubbed. Real Windows/Astra pilot checks remain required.\n', encoding='utf-8')
    files = sorted(path for path in stage.rglob('*') if path.is_file())
    (stage / 'SHA256SUMS.txt').write_text(''.join(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.relative_to(stage).as_posix() + '\n' for path in files))
    files.append(stage / 'SHA256SUMS.txt')
    archive = DIST / ('CM-Astra-' + VERSION + '-school-distribution.zip')
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as zipped:
        for path in files:
            zipped.write(path, 'CM-Astra/' + path.relative_to(stage).as_posix())
    with zipfile.ZipFile(archive) as zipped:
        assert zipped.testzip() is None
        for path in files:
            assert zipped.read('CM-Astra/' + path.relative_to(stage).as_posix()) == path.read_bytes()
    print('Built and tested:', archive)
