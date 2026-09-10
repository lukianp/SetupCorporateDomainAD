@echo off
REM Reassemble the 3 GitHub parts back into APPMON-Stack-Cutover-prod.zip, then verify.
REM Run on the destination in the folder holding .001/.002/.003
copy /b APPMON-Stack-Cutover-prod.zip.001+APPMON-Stack-Cutover-prod.zip.002+APPMON-Stack-Cutover-prod.zip.003 APPMON-Stack-Cutover-prod.zip
certutil -hashfile APPMON-Stack-Cutover-prod.zip SHA256
echo Compare with APPMON-Stack-Cutover-prod.zip.sha256 - must match.
