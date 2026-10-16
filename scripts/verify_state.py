#!/usr/bin/env python3
"""Bounded SQL/state integration check using canonical config; creates temporary objects."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
from configuration import ROOT, PROJECT, ConfigError, load, render, write_artifacts


def main():
    try:
        flags,policy,obs,env,compose=load()
        if not flags['analysis.session_behavior']:
            raise ConfigError('State verification requires analysis.session_behavior=true')
        write_artifacts(render(flags,policy,obs,compose))
        pwsh=shutil.which('pwsh') or shutil.which('powershell')
        if not pwsh:
            bundled=Path(os.environ.get('USERPROFILE',''))/'.cache/codex-runtimes/codex-primary-runtime/dependencies/native/powershell/pwsh.exe'
            if bundled.is_file(): pwsh=str(bundled)
        if not pwsh: raise ConfigError('PowerShell is required for the existing state integration check')
        env.update(HONEYPOT_CONFIGURED=PROJECT,COMPOSE_PROJECT_NAME=PROJECT,COMPOSE_FILE='',COMPOSE_PROFILES='')
        result=subprocess.run([pwsh,'-NoProfile','-File',str(ROOT/'tests/state/validate_authoritative_state.ps1'),
                               '-ComposeFile',str(ROOT/'.runtime/compose.yaml')],cwd=ROOT,env=env,capture_output=True,text=True)
        output=result.stdout+result.stderr
        for key,value in env.items():
            if any(word in key.lower() for word in ('password','secret','token')) and len(value)>=4:
                output=output.replace(value,'[REDACTED]')
        (ROOT/'.runtime/state-verification.txt').write_text(output,encoding='utf-8')
        print(output,end='')
        return result.returncode
    except (ConfigError,OSError) as exc:
        print(str(exc) if isinstance(exc,ConfigError) else 'State check could not execute; check local tools.',file=sys.stderr)
        return 1


if __name__=='__main__':
    sys.exit(main())
