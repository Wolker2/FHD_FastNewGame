#!/usr/bin/env python3
"""Rebuild FHD FastNewGame and its supplied settings; external loader DLLs excluded."""
import argparse,hashlib,json,os,platform,shutil,subprocess,sys,tempfile,zipfile,zlib
from pathlib import Path
ROOT=Path(__file__).resolve().parent
PREFIX='Mods/FHD_MODS/FHD_FastNewGame/'
sys.path.insert(0,str(ROOT/'tools'))
from get_toolchain import prepare
from compile_srhd_dat import build_bp,parse_blockpar,parse_bp_raw,unpack_dat_bytes,ser_bp_block

def load(path):return json.loads(Path(path).read_text(encoding='utf-8'))
def sha(data):return hashlib.sha256(data).hexdigest()
def rebuild(toolchain,exe=None):
    tools=prepare(toolchain);env=os.environ.copy();env['PATH']=str(tools/'usr/bin')+os.pathsep+env.get('PATH','');env['LD_LIBRARY_PATH']=str(tools/'usr/lib/x86_64-linux-gnu')+os.pathsep+env.get('LD_LIBRARY_PATH','')
    compiler=subprocess.check_output(['gcc','--version'],env=env,text=True).splitlines()[0];linker=subprocess.check_output(['ld','--version'],env=env,text=True).splitlines()[0]
    with tempfile.TemporaryDirectory(prefix='fastnewgame-source-build-') as td:
        root=Path(td);shutil.copytree(ROOT/'SOURCE',root/'SOURCE',ignore=shutil.ignore_patterns('__pycache__','*.pyc'));(root/'Native').mkdir()
        p=subprocess.run(['bash',str(root/'SOURCE/Native/build.sh')],env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        if p.returncode:print(p.stdout);raise RuntimeError('Native source build failed')
        dllpath=root/'Native/FHD_FastNewGame.XenoPlugin.dll';dll=dllpath.read_bytes()
        build_bp(root/'SOURCE/CFG/Main.txt',root/'Main.dat');dat=(root/'Main.dat').read_bytes()
        assert ser_bp_block(parse_bp_raw(unpack_dat_bytes(dat,0xb1e8c689)))==ser_bp_block(parse_blockpar(root/'SOURCE/CFG/Main.txt'))
        files={q.relative_to(ROOT/'settings').as_posix():q.read_bytes() for q in (ROOT/'settings').rglob('*') if q.is_file()}
        files[PREFIX+'ModuleInfo.txt']=(root/'SOURCE/ModuleInfo.txt').read_bytes().decode('utf-8').encode('cp1251');files[PREFIX+'CFG/Main.dat']=dat
        for target in (PREFIX+'Native/FHD_FastNewGame.XenoPlugin.dll','XenoNative/Plugins/FHD_FastNewGame/FHD_FastNewGame.XenoPlugin.dll'):files[target]=dll
        expected=load(ROOT/'original-file-sha256.json');assert set(files)==set(expected)
        actual={n:sha(b) for n,b in files.items()};changed=[n for n in files if actual[n]!=expected[n]]
        import pefile
        pe=pefile.PE(data=dll);exports={e.name.decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name};wanted={'XenoPlugin_Query','XenoPlugin_Initialize','_XenoPlugin_Query@4','_XenoPlugin_Initialize@4','FHDFastNewGame_Init'}
        assert pe.FILE_HEADER.Machine==0x14c and pe.OPTIONAL_HEADER.Magic==0x10b and exports==wanted
        assert not getattr(pe,'DIRECTORY_ENTRY_IMPORT',[]),'Freestanding plugin unexpectedly imports a DLL'
        assert files[PREFIX+'Native/FHD_FastNewGame.XenoPlugin.dll']==files['XenoNative/Plugins/FHD_FastNewGame/FHD_FastNewGame.XenoPlugin.dll']
        from configparser import ConfigParser
        def ini(name):
            c=ConfigParser();c.read_string(files[name].decode('utf-8-sig'));return c
        assert ini('XenoNative.ini').getint('Core','AutoRestartNativeMods')==0
        assert ini(PREFIX+'Native/FHD_FastNewGame.XenoPlugin.ini').getint('Plugin','Enabled')==0
        assert ini('XenoNative/Plugins/FHD_FastNewGame/XenoNativePlugin.ini').getint('Plugin','Enabled')==1
        native=None
        if exe:
            from verify_native import verify
            native=verify(dllpath,Path(exe).resolve())
        report={'status':'PASS' if not changed else 'BUILT: differs from original','version':'0.2.3 FIXED','scoped_runtime_files':len(files),'byte_identical_files':len(files)-len(changed),'different_files':changed,'sha256':actual,'plugin_copies_identical':True,'plugin_pe32_i386':True,'plugin_exports':sorted(exports),'plugin_imported_dlls':[],'dat_roundtrip_passed':True,'configuration_loader_invariants_passed':True,'native_probe':native,'compiler':compiler,'linker':linker,'python':platform.python_version(),'zlib':zlib.ZLIB_RUNTIME_VERSION,'native_build_log':p.stdout,'prebuilt_runtime_inputs_used':False,'production_source_modified':False,'third_party_loader_binaries_bundled':False,'full_original_distribution_reproduced':False,'full_game_executed':False,'github_workflow_executed':False}
        return files,report

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--toolchain',type=Path,default=ROOT/'.toolchain');p.add_argument('--verify-original',action='store_true');p.add_argument('--exe',type=Path);p.add_argument('--output-dir',type=Path,default=ROOT/'dist');a=p.parse_args()
    files,report=rebuild(a.toolchain,a.exe)
    if a.verify_original and report['different_files']:raise SystemExit('Original hash mismatch: '+repr(report['different_files']))
    out=a.output_dir;out.mkdir(parents=True,exist_ok=True);target=out/'FHD_FastNewGame_0.2.3_MOD_ONLY_FROM_SOURCE.zip'
    with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for name,data in sorted({**files,'INSTALL_SCOPE_RU.txt':(ROOT/'INSTALL_SCOPE_RU.txt').read_bytes()}.items()):
            info=zipfile.ZipInfo(name,(2026,10,29,0,0,0));info.external_attr=0o100644<<16;z.writestr(info,data,compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
    with zipfile.ZipFile(target) as z:assert z.testzip() is None
    report['generated_scope_notice_files']=1;report['distribution_files']=len(files)+1;report['output_sha256']=sha(target.read_bytes());(out/'build-report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'files':len(files),'byte_identical_files':report['byte_identical_files'],'native_checks':report['native_probe']['count'] if report['native_probe'] else None,'external_loader_bundled':False}))
if __name__=='__main__':main()
