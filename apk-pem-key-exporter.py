import zipfile
import re
import os
import base64

def extract_apk(apk_path):
    with zipfile.ZipFile(apk_path, 'r') as zip_ref:
        zip_ref.extractall("temp_apk")
        return zip_ref.namelist()

def find_secrets_in_content(content):
    secret_patterns = [
        r'-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----',
        r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
        r'-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----',
        r'-----BEGIN ENCRYPTED PRIVATE KEY-----.*?-----END ENCRYPTED PRIVATE KEY-----'
    ]
    
    secrets_found = []
    
    for pattern in secret_patterns:
        matches = re.findall(pattern, content, re.DOTALL)
        if matches:
            secrets_found.extend(matches)
    
    return secrets_found

def decode_base64_and_find_secrets(base64_content):
    try:
        decoded_bytes = base64.b64decode(base64_content)
        decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
        return find_secrets_in_content(decoded_str)
    except Exception as e:
        return []  

def scan_apk_for_secrets(apk_path):
    files = extract_apk(apk_path)
    print(f"{len(files)} file found.")
    
    for file_name in files:
        with open(f"temp_apk/{file_name}", 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
            
            base64_pattern = re.compile(r'([A-Za-z0-9+/=]{20,})') 
            base64_matches = base64_pattern.findall(content)
            
            for base64_match in base64_matches:
                secrets = decode_base64_and_find_secrets(base64_match)
                if secrets:
                    print(f"{file_name} Suspicious content found in file: (Base64 decoded):")
                    for secret in secrets:
                        print(secret)
                    print("\n" + "="*50 + "\n")
            
            secrets = find_secrets_in_content(content)
            if secrets:
                print(f"{file_name} Suspicious content found in file:")
                for secret in secrets:
                    print(secret)
                print("\n" + "="*50 + "\n")

apk_file_path = "example.apk" 

if os.path.exists(apk_file_path):
    scan_apk_for_secrets(apk_file_path)
else:
    print("APK file not found!")
