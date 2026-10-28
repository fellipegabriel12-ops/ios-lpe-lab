@echo off
rem o_c_run_install.cmd - launch the self-serve install (O-C / session "jailbreak 3")
rem   usage: o_c_run_install.cmd [app_path] [serial]
rem Kept as a .cmd because the workspace path contains a space and PowerShell's
rem Start-Process argument array mangles quoted args. cmd handles it correctly.
rem RUST_LOG=debug + RUST_BACKTRACE=1 because a panic's text is otherwise swallowed.
set APP=%~1
if "%APP%"=="" set APP=ci-out\dist6\VT4.ipa
set SERIAL=%~2
if "%SERIAL%"=="" set SERIAL=CK0773N6TM
cd /d "G:\op lab\iphone-control\jailbreak"
set RUST_LOG=debug
set RUST_BACKTRACE=1
"C:\Program Files\Python313\python.exe" o_c_jb.py install --app "%APP%" --serial "%SERIAL%" --log ".o_c\install.log"
