@echo off
if exist "%~dp0semantic-profiler.exe" (
  "%~dp0semantic-profiler.exe" %*
  exit /b %ERRORLEVEL%
)
if exist "%~dp0target\release\semantic-profiler.exe" (
  "%~dp0target\release\semantic-profiler.exe" %*
  exit /b %ERRORLEVEL%
)
echo error: semantic-profiler.exe not found beside %~nx0 or in target\release\ (build with: cargo build --release --locked) 1>&2
exit /b 127
