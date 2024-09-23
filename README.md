##ProcessHollowPython

Automated Tool for Process Hollowing with AES Encryption

ProcessHollowPython is a Python-based tool that automates process hollowing and shellcode injection using AES encryption for enhanced security.

Features:
Process Hollowing Automation: The script ProcessHollowAutomation.py takes shellcode.bin as input and generates a C# script (output.cs) that performs the process hollowing in a target process (e.g., svchost.exe).

AES Encryption: The shellcode is encrypted using a 256-bit AES key generated randomly on each execution, making the injection more secure and difficult to reverse-engineer.

Customizable Output: The C# code template includes encrypted shellcode, AES key, and initialization vector (IV) to decrypt the shellcode and perform the injection.

Usage:
bash
Copiar código
python3 ProcessHollowAutomation.py shellcode.bin output.cs
The script will generate a C# file (output.cs) that can be compiled and used for process hollowing with the encrypted shellcode.
How it works:
AES Encryption: The shellcode is read from the file, padded, and encrypted using AES in CBC mode with a randomly generated IV and key.
C# Template Generation: A C# template is generated, which decrypts the shellcode at runtime and injects it into the target process (svchost.exe).
Process Injection: The resulting C# script performs process hollowing by injecting the decrypted shellcode into the remote process.
