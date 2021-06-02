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

def intersect(lista, listb):
    return list(set(lista) & set(listb))

# takes a list of queries
# returns a dictionary with key as id and value as query data
def queryToDict(queries):
    dictionary = {}
    for query in queries:
        dictionary[query.id] = query.to_dict()
    return dictionary

# takes a token
# returns token's user uid if valid
# else returns None
def getUIDFromToken(token: str) -> Optional[str]:
    try:
        decoded_token = auth.verify_id_token(token)
        return decoded_token["uid"]
    except:
        return None

# takes a uid
# returns data belonging to the uid
def getUserDataByUID(uid: str):
    user = table.document(uid).get()
    return user.to_dict()
    
# takes a list of sites
# returns dict of user data belonging to any of the sites
def getUsersBySites(sites: List[str]):
    users = table.where(u'sites', u'array_contains_any', sites).stream()
    return queryToDict(users)

### ----------------------------------------
### ----------- COMMON RESPONSES -----------
### ----------------------------------------

notAuthorizedJSON = JSONResponse(content={"response": "unauthorized"}, status_code=401)
invalidDataJSON = JSONResponse(content={"response": "bad request"}, status_code=400)
failedRequestJSON = JSONResponse(content={"response": "server failed to handle request"}, status_code=500)
successfulJSON = JSONResponse(content={"response": "successful request"}, status_code=200)
    
### ----------------------------------------
### ---------- ACCOUNT MANAGEMENT ----------
### ----------------------------------------

# ----- Get account data -----
@app.get("/accounts")
def getAccount(token: str, uid: Optional[str] = None):
    requestingUserUID = getUIDFromToken(token)
    if requestingUserUID == None:
        return JSONResponse(content={"response": "invalid token"}, status_code=400)
    
    requestingUserData = getUserDataByUID(requestingUserUID)
    
    # return user uid and data
    if uid != None:
        queriedUser = getUserDataByUID(uid)
        
        if queriedUser == None:
            return JSONResponse(content={"response": "queried uid does not exist."}, status_code=400)
        
        if requestingUserData["userType"] == UserTypes.default_user:
            return notAuthorizedJSON
        
        if requestingUserData["userType"] == UserTypes.admin:
            return queriedUser
        
        if requestingUserData["userType"] == UserTypes.site_manager:
            if len(intersect(requestingUserData["sites"], queriedUser["sites"])) > 0:
                return queriedUser
            return notAuthorizedJSON
    
    #return all accounts which user has permission for
    else:
        if requestingUserData["userType"] == UserTypes.admin:
            allUsers = table.get()
            return queryToDict(allUsers)
        
        elif requestingUserData["userType"] == UserTypes.site_manager:
            return getUsersBySites(requestingUserData["sites"])
        
    # if all above fails
    return invalidDataJSON

# ----- Removing account -----
@app.delete("/accounts")
def deleteAccount(token:str, uid: str):
    requestingUserUID = getUIDFromToken(token)
    if requestingUserUID == None:
        return JSONResponse(content={"response": "invalid token"}, status_code=400)
    
    requestingUserData = getUserDataByUID(requestingUserUID)
    
    if requestingUserData["userType"] == UserTypes.default_user:
        return notAuthorizedJSON
    
    if requestingUserData["userType"] == UserTypes.admin:
        table.document(uid).delete()
        auth.delete_user(uid)
        return successfulJSON
    
    if requestingUserData["userType"] == UserTypes.site_manager:
        userToDelete = getUserDataByUID(uid)
        if len(intersect(requestingUserData["sites"], userToDelete["sites"])) > 0:
            table.document(uid).delete()
            auth.delete_user(uid)
            return successfulJSON
        return notAuthorizedJSON
    
    return invalidDataJSON

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
