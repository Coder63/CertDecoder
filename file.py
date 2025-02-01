
from fastapi import FastAPI, Request, Form
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
import subprocess
from concurrent.futures import ThreadPoolExecutor
import os
from OpenSSL import crypto
import hashlib

app = FastAPI()
templates = Jinja2Templates(directory="templates")
executor = ThreadPoolExecutor(max_workers=5)  # Adjust the number of workers as needed

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "output": ""})

@app.post("/", response_class=HTMLResponse)
async def decode(request: Request, input_data: str = Form(...)):
    future = executor.submit(decode_cert_or_csr, input_data)
    output, filename = future.result()
    return templates.TemplateResponse("index.html", {"request": request, "output": output, "filename": filename})


def decode_cert_or_csr(input_data):
    try:
        # First, try to process as a certificate
        result = subprocess.run(
            ["openssl", "x509", "-text", "-noout"],
            input=input_data,
            capture_output=True,
            text=True,
            check=True
        )
        obj_type = "Certificate"
        obj = crypto.load_certificate(crypto.FILETYPE_PEM, input_data.encode())
    except subprocess.CalledProcessError:
        # If it fails, try to process as a CSR
        try:
            result = subprocess.run(
                ["openssl", "req", "-text", "-noout"],
                input=input_data,
                capture_output=True,
                text=True,
                check=True
            )
            obj_type = "CSR"
            obj = crypto.load_certificate_request(crypto.FILETYPE_PEM, input_data.encode())
        except subprocess.CalledProcessError as e:
            return f"Error: {e.stderr}", None

    # Calculate MD5 hash
    md5_hash = hashlib.md5(input_data.encode()).hexdigest()

    # Prepend MD5 hash to the output
    output = f"MD5 Hash: {md5_hash}\n\n" + result.stdout
    cn = obj.get_subject().CN
    filename = f"{cn}_{obj_type}.txt"
    
    # Save output to file
    with open(filename, 'w') as f:
        f.write(output)
    
    return output, filename

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

