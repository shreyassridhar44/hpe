import os

file_path = r"c:\Users\Lenovo\demo\demo\vault\init\init-vault.sh"
with open(file_path, "rb") as f:
    content = f.read()

# Replace Windows CRLF with Unix LF
content = content.replace(b"\r\n", b"\n")

with open(file_path, "wb") as f:
    f.write(content)

print(f"✅ Successfully converted line endings to LF for {file_path}")
