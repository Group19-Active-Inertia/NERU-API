from fastapi import FastAPI
from fastapi.responses import JSONResponse
import firebase_admin
from firebase_admin import credentials, auth, db, firestore
# import google-cloud-firestore

from enum import Enum
from typing import List, Optional, TypedDict, Dict
from pydantic import BaseModel

app = FastAPI()


cred = credentials.Certificate("key.json")
firebase_admin.initialize_app(
    cred, 
    {'databaseURL': "https://create-active-inertia-default-rtdb.europe-west1.firebasedatabase.app",
     'projectId': "create-active-inertia",
     }
    )

fs = firestore.client()

table = fs.collection('users')

#### ----------------------------------
#### ------------ CLASSES -------------
#### ----------------------------------

class UserTypes(str, Enum):
    admin = "admin"
    site_manager = "sitemanager"
    default_user = "default"
    
class UserBase(BaseModel):
    sites: List[str]
    accountType: UserTypes
    
class UserEdit(UserBase):
    uid: str
    
class UserCreate(UserBase):
    email: str
    password: str
    
### ----------------------------------------
### ----------- HELPER FUNCTIONS -----------
### ----------------------------------------

def verifyToken(token: str) -> Optional[str]:
    try:
        decoded_token = auth.verify_id_token(token)
        return decoded_token["uid"]
    except:
        return None

def getUserByUID(uid: str):
    user = table.document(uid).get()
    return {uid: user.to_dict()}
    
def getUsersByRange(uid: str):
    pass
    
def getUsersBySites(sites: List[str]):
    users = table.where(u'sites', u'array_contains_any', sites).stream()
    dictionary = {}
    
    for user in users:
        dictionary[user.id] = user.to_dict()
    return dictionary

### ----------------------------------------
### ----------- COMMON RESPONSES -----------
### ----------------------------------------

notAuthorizedJSON = JSONResponse(content={"response": "unauthorized"}, status_code=401)
invalidDataJSON = JSONResponse(content={"response": "bad request"}, status_code=400)
successfulJSON = JSONResponse(content={"response": "successful transaction"}, status_code=200)
    
    
### ----------------------------------------
### ---------- ACCOUNT MANAGEMENT ----------
### ----------------------------------------

# ----- Get account data -----
@app.get("/accounts")
def getAccount(token: str, getUid: Optional[str] = None):
    requestingUserUid = verifyToken(token)
    if requestingUserUid == None:
        return invalidDataJSON
    
    requestingUserData = getUserByUID(requestingUserUid)
    requestingUserPermission = requestingUserData["userType"]
    
    if requestingUserPermission == UserTypes.admin:
        return getUserByUID(getUid)
    elif requestingUserPermission == UserTypes.site_manager:
        for site in requestingUserData["sites"]:
            if getUid == None:
                docs = db.collections('users').where()
                # todo
    

    
    return {}

# ----- Removing account -----
@app.delete("/accounts")
def deleteAccount(uid: str):
    return {}

# ----- Adding account -----
@app.post("/accounts")
def addAccount(user: UserCreate):
    return {}

# ----- Edit account data -----
@app.put("/accounts")
def editAccount(user: UserEdit):
    # # Atomically add a new region to the 'regions' array field.
    # city_ref.update({u'regions': firestore.ArrayUnion([u'greater_virginia'])})

    # # // Atomically remove a region from the 'regions' array field.
    # city_ref.update({u'regions': firestore.ArrayRemove([u'east_coast'])})
    return {}

### ----------------------------------------
### ------------ SITE MANAGEMENT -----------
### ----------------------------------------

# ----- Add site to database -----
@app.post("/site")
def addSite(name: str):
    return {}

# ----- Delete site from database -----
@app.delete("/site")
def deleteSite(name: str):
    return {}

### ----------------------------------------
### ---------- LOGGING IN TO NERU ----------
### ----------------------------------------

# ----- Log-in to NERU -----
@app.post("/nerulogin")
def NERULogin(email: str, password: str):
    return {}

# ----- Choose NERU location after logging in -----
@app.put("/choosesite")
def chooseSite(site: str):
    return {}

### -----------------------------------------
### --------- LOGGING IN TO WEBSITE ---------
### -----------------------------------------

# ----- Get permission -----
@app.get("/weblogin")
def webLogin(email: str, password: str):
    return {}
