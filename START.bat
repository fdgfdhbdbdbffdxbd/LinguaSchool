@echo off
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe py -3 -m venv .venv
if errorlevel 1 goto fail
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto fail
.venv\Scripts\python.exe configure.py
if errorlevel 1 goto fail
.venv\Scripts\python.exe -m flask --app app init-db
if errorlevel 1 goto fail
echo First run: in another terminal execute .venv\Scripts\python.exe -m flask --app app seed
echo Save the generated passwords. Open http://127.0.0.1:5000
.venv\Scripts\python.exe -m flask --app app run --host 127.0.0.1
pause
exit /b
:fail
echo Setup failed. Read the error above.
pause
