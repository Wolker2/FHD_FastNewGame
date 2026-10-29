#!/usr/bin/env python3
"""Fetch/extract exact historical Debian compiler packages locally, never install them."""
import concurrent.futures,hashlib,json,platform,shutil,subprocess,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def prepare(directory):
    directory=Path(directory).resolve();manifest=json.loads((ROOT/'toolchain-packages.json').read_text())
    if platform.machine() not in ('x86_64','amd64'):raise RuntimeError('Pinned compiler packages require Linux x86-64')
    if not shutil.which('dpkg-deb'):raise RuntimeError('dpkg-deb is required to extract the compiler packages')
    directory.mkdir(parents=True,exist_ok=True)
    def download(item):
        target=directory/item['name']
        if not target.exists() or hashlib.sha256(target.read_bytes()).hexdigest()!=item['sha256']:
            temporary=target.with_suffix('.download')
            with urllib.request.urlopen(item['url'],timeout=60) as response,temporary.open('wb') as f:shutil.copyfileobj(response,f)
            if temporary.stat().st_size!=item['size'] or hashlib.sha256(temporary.read_bytes()).hexdigest()!=item['sha256']:
                temporary.unlink(missing_ok=True);raise RuntimeError('Compiler package checksum mismatch: '+item['name'])
            temporary.replace(target)
        return target
    packages=list(concurrent.futures.ThreadPoolExecutor(max_workers=4).map(download,manifest))
    marker=directory/'packages-verified.json'
    if not marker.exists() or marker.read_text()!=json.dumps(manifest,sort_keys=True):
        for package in packages:subprocess.run(['dpkg-deb','-x',str(package),str(directory)],check=True)
        for name,target in [('gcc','gcc-12'),('as','x86_64-linux-gnu-as'),('ld','x86_64-linux-gnu-ld')]:
            p=directory/'usr/bin'/name
            if not p.exists():p.symlink_to(target)
        marker.write_text(json.dumps(manifest,sort_keys=True))
    return directory
if __name__=='__main__':print(prepare(ROOT/'.toolchain'))
