# PSEvade
Evade Windows Defender by encrypting PowerShell scripts or modules with Python, then decrypting and executing them in memory.

# Usage
1. Encrypt with Python on your attack machine.
2. Deliver the encrypted script or module to the victim.
3. Deliver and load (by dot-sourcing) the decrypt script.

> **NOTE:** This was tested with PowerView and a few other scripts. If you encounter an issue, please let me know.
