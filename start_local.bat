@echo off
setlocal
cd /d "%~dp0"
if not exist .env (
  echo [ERROR] Copy .env.example to .env and set the administrator password first.
  pause
  exit /b 1
)
if not exist .venv (
  py -m venv .venv
)
call .venv\Scripts\activate.bat
python -m pip install -r requirements.txt
set COOKIE_SECURE=0
python -m uvicorn app:app --host 127.0.0.1 --port 8000

