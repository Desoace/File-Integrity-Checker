COMPANY NAME- CODTECH IT SOLUTIONS
NAME- DHRUV DABRAL
INTERN ID- CT04DG2535
DOMAIN- CYBERSECURITY AND ETHICAL HACKING
DURATION- 4 WEEKS
MENTOR- NEELAM SANTOSH



The File Integrity Checker is a Python-based tool designed to monitor and verify file integrity by calculating and comparing cryptographic hash values. This tool addresses the critical security need of detecting unauthorized file modifications, which could indicate malware, tampering, or corruption. The implementation uses Python's built-in hashlib library to compute various hash algorithms including MD5, SHA1, SHA256, and SHA512, providing flexibility in choosing the appropriate level of security. The tool works by creating a baseline snapshot of files through hash calculation and storing these hashes along with metadata such as timestamps and file paths in a JSON database. When performing integrity checks, it recalculates the hash of each monitored file and compares it with the stored baseline value. Any mismatch indicates the file has been modified since the last check. The tool features a command-line interface built with argparse, allowing users to add files for monitoring, check individual files or all monitored files at once, update hashes after legitimate modifications, and remove files from monitoring. The implementation includes efficient file reading in chunks to handle large files without consuming excessive memory. Each file's status is tracked with visual indicators showing whether files are intact, modified, or deleted. The tool maintains a persistent database that survives between program runs, enabling long-term file monitoring. Error handling ensures the tool gracefully manages scenarios like missing files, permission errors, and corrupted data. The JSON storage format makes the hash database human-readable and easily portable across systems. This tool is particularly useful for system administrators monitoring critical configuration files, developers tracking code integrity, and security professionals establishing file baselines for forensic analysis.


#OUTPUT
<img width="1115" height="376" alt="Image" src="https://github.com/user-attachments/assets/b6fd122e-d061-4839-9e34-61dfdc66b5d1" />
<img width="925" height="255" alt="Image" src="https://github.com/user-attachments/assets/3c3c86b0-d036-47a5-a7e5-a05b19fe5af5" />
