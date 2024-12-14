from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from pymongo import MongoClient
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import os
from copy import copy
from langchain_openai import AzureChatOpenAI
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
import json
import requests

print(datetime.now())

app = FastAPI()

API_KEY = "c2cdf8b5cd6b4d86814b9addf0c394f6"
API_VERSION = "2024-02-15-preview"
ENDPOINT = "https://yubi-genai-eastus2.openai.azure.com/"

common_params = {
    "api_key": API_KEY,
    "api_version": API_VERSION,
    "azure_endpoint": ENDPOINT,
    "temperature": 0.0,
    "model_kwargs": {
        "frequency_penalty": 0,
        "presence_penalty": 0,
        "seed": 99
    }
}

# MODEL: GPT 3.5 TURBO
# llm_gpt35_turbo = AzureChatOpenAI(deployment_name="gpt-35-turbo", **common_params)

# MODEL: GPT4o
llm_gpt4o = AzureChatOpenAI(deployment_name="gpt4o", **common_params)

# MongoDB connection
client = MongoClient(os.getenv("DATABASE_URL"))
db = client["journey_db"]
users_collection = db["users"]

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your_secret_key_here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Pydantic models
class User(BaseModel):
    email: str
    password: str

class UserInDB(BaseModel):
    email: str
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

import datetime
config_json = {
    "invoice": {
        "ocr_ext": {
            "invoice_number": "Invoice Identifier",
            "invoice_value": "Value of invoice",
            "seller_name": "Seller Name",
            "seller_address": "Seller Address"
        },
        "ocr_val": {
            "invoice_number": "present",
            "invoice_value": ">100"
        },
        "ocr_verify": {}
    },

    "PO": {
        "ocr_ext": {
            "po_date": "Purchase Order Date"
        },
        "ocr_val": {
            "po_date": f">{datetime.datetime.now().strftime('%Y-%m-%d')}"
        },
        "ocr_verify": {}
    },

    "Aadhaar": {
        "ocr_ext": {
            "name": "Full Name",
            "uid": "Aadhaar Number",
            "dob": "Date of Birth",
            "address": "Address"
        },
        "ocr_val": {
            "uid": "present",  # Ensure Aadhaar number is present
            "dob": "present"   # Ensure Date of Birth is present
        },
        "ocr_verify": {
            # Add verification logic here (e.g., checksum, API calls)
        }
    },

    "PAN": {
        "ocr_ext": {
            "name": "Full Name",
            "pan": "PAN Number"
        },
        "ocr_val": {
            "pan": "present"  # Ensure PAN number is present
        },
        "ocr_verify": {
            # Add verification logic here (e.g., checksum)
        }
    },

    "DrivingLicense": {
        "ocr_ext": {
            "name": "Full Name",
            "license_number": "License Number",
            "dob": "Date of Birth",
            "address": "Address",
            "valid_from": "Valid From",
            "valid_to": "Valid To" ,
        },
        "ocr_val": {
            "license_number": "present",  # Ensure License number is present
            "dob": "present",            # Ensure Date of Birth is present
            "valid_from": "present",      # Ensure Valid From date is present
            "valid_to": "present"        # Ensure Valid To date is present
        },
        "ocr_verify": {
            # Add verification logic here (e.g., API calls to relevant authorities)
        }
    }
}

def prompt_builder(ocr_report):
    ocr_parser_prompt = f"""Report: {ocr_report}
    Document Extraction Output -
    In this section Each JSON object in the list should correspond to an individual document and should include the following key-value pairs:
    1. document_type: The type of the document.
    2. digital_flag: A Boolean value indicating whether the document is digital (true) or scanned (false).
    3. signature_flag : A Boolean value indicating whether the signature is available (true) in the document or not available (false). - 
    4. ocr_extraction : Under each JSON object I need the following details extracted and stored under the key.. ensure all the numbers are standardized
    5. validation_criteria : Each validation must be Boolean - Under each JSON object i need the document specific validation criteria, validation is rendered as True or False based on the conditions given in the Validation Criteria section under each specific document below
    If Validation Criteria is not mentioned below a document - leave that section empty

    Extract only the list of documents present in the below json
    """

    for key in config_json:
        ocr_ext_prompt = config_json[key]['ocr_ext']
        ocr_ext_validate = config_json[key]['ocr_val']

        ocr_parser_prompt +=  f"""

        DOCUMENT NAME - {key}

        ocr_extraction:
        {str(ocr_ext_prompt).replace("{","").replace("}","")}



        validation_criteria:
        {str(ocr_ext_validate).replace("{","").replace("}","")}


        """

    print(ocr_parser_prompt)
    return ocr_parser_prompt


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Compare the plain password with the hashed password using bcrypt.
    """
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except ValueError:
        return False

def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=15)) -> str:
    """
    Creates a JWT token with the given data and an optional expiration time.
    """
    to_encode = data.copy()
    # Set the expiration time using datetime.now()
    expire = datetime.now() + expires_delta  # Ensure datetime is properly imported
    to_encode.update({"exp": expire})
    
    # Create the encoded JWT token
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> str:
    """
    Verifies the given JWT token and returns the user identifier if valid.
    """
    try:
        # Decode the JWT token and get the payload
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # Return the subject (user identifier) from the token payload
        return payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=403, detail="Could not validate credentials")

def add_user_to_db(user: UserInDB):
    users_collection.insert_one(user.dict())

@app.post("/signup/")
def signup(user: User):
    if users_collection.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    user_in_db = UserInDB(email=user.email, hashed_password=hashed_password)
    add_user_to_db(user_in_db)
    return {"message": "User created successfully"}

@app.post("/signin/", response_model=Token)
def signin(user: User):
    try:
        # Ensure database connection is active
        if users_collection is None:
            raise HTTPException(status_code=500, detail="Database connection error")
        # Find the user in the database
        db_user = users_collection.find_one({"email": user.email})
        if db_user is None:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        # Get the hashed password from the database
        hashed_password = db_user.get("hashed_password")
        if not hashed_password:
            raise HTTPException(status_code=500, detail="Password not found in the database")
        # Compare the plain password with the hashed password
        if not verify_password(user.password, hashed_password):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        # Generate a JWT token for the user
        access_token = create_access_token(data={"sub": user.email})
        return {"access_token": access_token, "token_type": "bearer"}
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        print(f"Signin Error: {e}")  # Log the error to the console
        raise HTTPException(status_code=500, detail=f"Internal server error: {e}")  # Include error details in the response




@app.get("/users/me/")
def read_users_me(token: str = Depends(verify_token)):
    return {"message": "This is a protected route!", "user": token}

@app.post("/ocr-extraction")
def ocr_extraction():
    api_url = 'https://unstract-poc.go-yubi.in/deployment/api/org_tD5Bn400PuKXKjtc/text_extractor/'
    headers = {
        'Authorization': 'Bearer 339c33bd-7dee-48d4-afa5-60d95d4b776c'
    }
    payload = {'timeout': 300, 'include_metadata': False}

    # Hardcoded file paths (replace these with actual file paths on your server)
    file_paths = [
        'aadhar.pdf'
    ]

    files = []
    for i, file_path in enumerate(file_paths):
        try:
            # Open the file and prepare it for the request
            file_obj = open(file_path, 'rb')
            files.append(('files', (f'file{i+1}', file_obj, 'application/octet-stream')))
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error reading file {file_path}: {str(e)}")

    try:
        # Send the request to the OCR API
        response = requests.post(api_url, headers=headers, data=payload, files=files)
        report = response.json()['message']['result'][-1]['result']
        report1 = copy(report)
        ocr_parser_prompt = prompt_builder(report1)
        prompt = PromptTemplate.from_template(ocr_parser_prompt)
        chain = LLMChain(llm=llm_gpt4o,prompt=prompt)
        ocr_response = chain.invoke({"report" : report1 })
        json_string1 = ocr_response['text'].strip('```json').strip('```')
        json_response1 = json.loads(json_string1)

        # Check for a successful response
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=f"OCR API Error: {response.text}")

        # Return the OCR extraction result (or you can parse the response here as needed)
        return json_response1

    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Error calling OCR API: {str(e)}")

    finally:
        # Ensure file handles are closed
        for _, (name, file_obj, mime_type) in files:
            file_obj.close()
