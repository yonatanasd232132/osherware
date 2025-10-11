polymorphic malware that uses indirect syscalls with randomised obfuscation that does not appear in code since decryption//encryption is generated using claude, code only appears during compiling//execution
osher_cohen_poly.py is called to modify the indirect syscall file which is malwery.cpp and creates a decryption file, 
main code is ran mamaliga.cpp, which fetches all of the files onto the AWS machine which runs the poly code and then fetches all the files into the victim machine
then compiling the decryptor into a dll so it could be called inside the main() func and then ran onto the encrypted dll malware which is then decrypted and ran as a DLL executing the malware secretly evading EDR's
