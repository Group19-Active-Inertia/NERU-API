from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import firebase_admin
from firebase_admin import credentials, auth, db, firestore
import requests

from enum import Enum
from typing import List, Optional, TypedDict, Dict
from pydantic import BaseModel, Field

tags_metadata = [
    {
        "name": "User Management",
        "description": "These endpoints are used to manage user data",
    },
    {
        "name": "Site Management",
        "description": "These endpoints are used to manage NERU site data",
    },
    {
        "name": "Login",
        "description": "These endpoints handle log-ins",
    },
]

app = FastAPI(openapi_tags=tags_metadata)

@app.get("/", include_in_schema=False)
def welcomePage():
    return {"API Works!":"Welcome!"}

cred = credentials.Certificate("key.json")
firebase_admin.initialize_app(
    cred, 
    {'databaseURL': "https://create-active-inertia-default-rtdb.europe-west1.firebasedatabase.app",
     'projectId': "create-active-inertia",
     }
    )

fs = firestore.client()

table = fs.collection('users')

#### ---------------------------------
#### -------- COMMON CLASSES ---------
#### ---------------------------------

class UserTypes(str, Enum):
    admin = "admin"
    site_manager = "sitemanager"
    default_user = "default"

#### --------------------------------
#### -------- INPUT CLASSES ---------
#### --------------------------------

class GetData(BaseModel):
    token: str = Field(..., example="q2uWM7esugFJhGptPtIItpF8OWxS6vr2CrQ1cMH81ZoXmQ........")
    
class GetUserData(GetData):
    uid: Optional[str] = Field(None, example="5dci23SoQXQIRQgXVwacYGNrrWS2")
    
class DelUserData(GetData):
    uid: str = Field(..., example="5dci23SoQXQIRQgXVwacYGNrrWS2")
    
class UserBase(GetData):
    sites: List[str] = Field([], example=["Birmingham", "London", "Newcastle"])
    userType: UserTypes = Field(UserTypes.default_user, example=UserTypes.site_manager)
    email: Optional[str] = Field(None, example="user@email.com")
    
class UserEdit(GetData):
    uid: str = Field(..., example="5dci23SoQXQIRQgXVwacYGNrrWS2")
    email: Optional[str] = Field(None, example="user@email.com")
    password: Optional[str] = Field(None, example="password123")
    userType: Optional[UserTypes] = Field(None, example=UserTypes.site_manager)
    
class UserCreate(UserBase):
    password: str = Field(..., example="password123")
    
class Login(BaseModel):
    email: str = Field(..., example="user@email.com")
    password: str = Field(..., example="password123")
    
class ChooseSite(GetData):
    site: str = Field(..., example="Nottingham")

#### ---------------------------------
#### -------- OUTPUT CLASSES ---------
#### ---------------------------------

class UserGet(BaseModel):
    sites: List[str] = Field(..., example=["Birmingham", "London", "Newcastle"])
    userType: UserTypes = Field(..., example=UserTypes.site_manager)
    email: str = Field(..., example="user@email.com")
    
class GetUserOut(BaseModel):
    __root__: Dict[str, UserGet] = Field(..., example={
        "5dci23SoQXQIRQgXVwacYGNrrWS2": {
            "email":"user@email.com",
            "userType": UserTypes.site_manager,
            "sites": ["Birmingham", "London", "Newcastle"]}})

class WebLoginOut(BaseModel):
    uid: str = Field(None, example="5dci23SoQXQIRQgXVwacYGNrrWS2")
    idToken: str = Field(..., example="q2uWM7esugFJhGptPtIItpF8OWxS6vr2CrQ1cMH81ZoXmQ........")
    refreshToken: str = Field(..., example="AGEhc0AijkK9xYrO3Iams2II8EQJr-uwncfej4amfxT-........")
    tokenExpiresIn: str = Field(..., example="3600")
    userType: UserTypes = Field(..., example=UserTypes.site_manager)
    sites: List[str] = Field(..., example=["Birmingham", "London", "Newcastle"])

class NeruLoginOut(BaseModel):
    pass

class SuccessfulOut(BaseModel):
    response: str = Field("successful request", example="successful request")
    
class AddUserOut(BaseModel):
    uid: str = Field(..., example="5dci23SoQXQIRQgXVwacYGNrrWS2")
    
### ----------------------------------------
### ----------- HELPER FUNCTIONS -----------
### ----------------------------------------

def intersect(lista, listb):
    return list(set(lista) & set(listb))

# takes a list of queries
# returns a dictionary with key as id and value as query data
def queryToDict(queries):
    if len(queries) == 1:
        try:
            return {queries[0].id: queries[0].to_dict()}
        except:
            return queries
        
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
    return queryToDict([user])


# takes a list of sites
# returns dict of user data belonging to any of the sites
def getUsersBySites(sites: List[str]):
    users = table.where(u'sites', u'array_contains_any', sites).stream()
    return queryToDict(users)


def createUser(user: UserCreate):
    newUser = auth.create_user(
        email=user.email,
        email_verified=True,
        password=user.password,
        disabled=False)
    
    newUserRecord = {
        "userType": user.userType,
        "sites": user.sites,
        "email": user.email,   
    }
    
    table.document(newUser.uid).set(newUserRecord)
    
    return newUser.uid

def editUser(user: UserEdit):
    # TODO: check if email already exists
    batch = fs.batch()
    ref = table.document(user.uid)
    
    if user.email != None and user.password != None:
        auth.update_user(user.uid, email=user.email, password=user.password)
        batch.update(ref, {"email":user.email})
        
    elif user.email != None:
        auth.update_user(user.uid, email=user.email)
        batch.update(ref, {"email":user.email})
        
    elif user.password != None:
        auth.update_user(user.uid, password=user.password)
        
    if user.userType != None:
        batch.update(ref, {'userType': user.userType})
        
    batch.commit()
    return
        

def loginUser(email: str, password: str):
    apiKey = "AIzaSyBkpEDGlj06SVpYzIbNr2KCIGfYhXBGysE"
    url = f"https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword?key={apiKey}"
    data = {
        "email": email,
        "password": password,
        "returnSecureToken": "true"
    }
    
    req = requests.post(url,data=data)
    
    if req.status_code == 200:
        reqJson = req.json()
        
        usefulData = {
            "uid": reqJson["localId"],
            "idToken": reqJson["idToken"],
            "refreshToken": reqJson["refreshToken"],
            "tokenExpiresIn": reqJson["expiresIn"],
        }
        
        return usefulData
    else:
        return None

### ----------------------------------------
### ----------- COMMON RESPONSES -----------
### ----------------------------------------

unauthorizedException = HTTPException(401, {"error": "unauthorized action"})
invalidDataException = HTTPException(400, {"error": "bad request"})
invalidTokenException = HTTPException(400, {"error": "invalid token"})
failedHandlingException = HTTPException(500, {"error": "server failed to handle request"})
invalidCredentialsException = HTTPException(400, {"error": "invalid credentials"})

successfulJSON = JSONResponse(content={"response": "successful request"}, status_code=200)
    
### ----------------------------------------
### ---------- ACCOUNT MANAGEMENT ----------
### ----------------------------------------

# ----- Get account data -----
@app.get("/accounts", tags=["User Management"], response_model=GetUserOut)
def get_user(token: str, uid: Optional[str] = None):
    requestingUserUID = getUIDFromToken(token)
    if requestingUserUID == None:
        return JSONResponse(content={"response": "invalid token"}, status_code=400)
    
    requestingUserData = getUserDataByUID(requestingUserUID)[requestingUserUID]
    # return user uid and data
    if uid != None:
        queriedUser = getUserDataByUID(uid)
        
        if queriedUser == None:
            return JSONResponse(content={"response": "queried uid does not exist."}, status_code=400)
        
        elif requestingUserData["userType"] == UserTypes.default_user:
            return unauthorizedException
        
        elif requestingUserData["userType"] == UserTypes.admin:
            return queryToDict(queriedUser)
        
        elif requestingUserData["userType"] == UserTypes.site_manager:
            if len(intersect(requestingUserData["sites"], queriedUser[uid]["sites"])) > 0:
                return queryToDict(queriedUser)
            
            return unauthorizedException
    
    #return all accounts which user has permission for
    else:
        if requestingUserData["userType"] == UserTypes.admin:
            allUsers = table.get()
            return queryToDict(allUsers)
        
        elif requestingUserData["userType"] == UserTypes.site_manager:
            return getUsersBySites(requestingUserData["sites"])
        
        else:
            return unauthorizedException
        
    # if all above fails
    return invalidDataException

# ----- Removing account -----
@app.delete("/accounts", tags=["User Management"], response_model=SuccessfulOut)
def delete_user(delUser: DelUserData):
    requestingUserUID = getUIDFromToken(delUser.token)
    if requestingUserUID == None:
        return invalidTokenException
    
    requestingUserData = getUserDataByUID(requestingUserUID)
    
    if requestingUserData["userType"] == UserTypes.default_user:
        return unauthorizedException
    
    if requestingUserData["userType"] == UserTypes.admin:
        table.document(delUser.uid).delete()
        auth.delete_user(delUser.uid)
        return successfulJSON
    
    if requestingUserData["userType"] == UserTypes.site_manager:
        userToDelete = getUserDataByUID(delUser.uid)
        if len(intersect(requestingUserData["sites"], userToDelete["sites"])) > 0:
            table.document(delUser.uid).delete()
            auth.delete_user(delUser.uid)
            return successfulJSON
        return unauthorizedException
    
    return invalidDataException

# ----- Adding user -----
@app.post("/accounts", tags=["User Management"], response_model=AddUserOut)
def add_user(addUser: UserCreate):
    
    def addSitesOnly():
        user = auth.get_user_by_email(addUser.email)
        addSitesToUser(addUser.uid, addUser.sites)
        return user.uid        
        
    requestingUserUID = getUIDFromToken(addUser.token)
    if requestingUserUID == None:
        raise invalidTokenException
    
    requestingUserData = getUserDataByUID(requestingUserUID)[requestingUserUID]
    
    if requestingUserData["userType"] == UserTypes.admin:
        
        # if user already exists
        try:
            uid = addSitesOnly()
         
        except:   
            uid = createUser(addUser)
            if uid == None:
                raise invalidDataException
        
        return JSONResponse(content={"uid": uid})
    
    if (requestingUserData["userType"] == UserTypes.site_manager and
        len(intersect(addUser.sites, requestingUserData["sites"])) == len(addUser.sites) and
        addUser.userType == UserTypes.default_user
        ):
            # if user already exists
            try:
                uid = addSitesOnly()
                
            # if user doesnt exist
            except:
                uid = createUser(addUser)
                if uid == None:
                    raise invalidDataException
            
            return JSONResponse(content={"uid": uid})
        
    raise unauthorizedException

# ----- Edit account data -----
@app.put("/accounts", tags=["User Management"], response_model=SuccessfulOut)
def edit_user(user: UserEdit):
    requestingUserUID = getUIDFromToken(user.token)
    if requestingUserUID == None:
        raise invalidTokenException
    
    requestingUserData = getUserDataByUID(requestingUserUID)[requestingUserUID]
    
    if not table.document(user.uid).get().exists:
        raise HTTPException(400, {"error": "user uid does not exist"})
    
    if requestingUserData["userType"] == UserTypes.admin:
        editUser(user)
        return successfulJSON
    
    elif (requestingUserData["userType"] == UserTypes.site_manager    and
        len(intersect(user.sites, requestingUserData["sites"])) > 0 and 
        user.userType == None
        ):
            editUser(user)
            return successfulJSON
        
    raise unauthorizedException

### ----------------------------------------
### ------------ SITE MANAGEMENT -----------
### ----------------------------------------

# # ----- Add site to database -----
# @app.post("/site", tags=["Site Management"], response_model=SuccessfulOut)
# def add_site(name: str):
#     return {}

# # ----- Delete site from database -----
# @app.delete("/site", tags=["Site Management"], response_model=SuccessfulOut)
# def delete_site(name: str):
#     return {}

# # ----- Delete site from database -----
# @app.delete("/site", tags=["Site Management"], response_model=SuccessfulOut)
# def edit_site(name: str):
#     return {}

### -----------------------------
### --------- WEB LOGIN ---------
### -----------------------------

# ----- Log-in to website -----
@app.post("/weblogin", tags=["Login"], response_model=WebLoginOut)
def web_login(login: Login):
    userData = loginUser(login.email, login.password)
    try:
        firestoreUserData = getUserDataByUID(userData["uid"])
        dataToSend = {**userData, **firestoreUserData}
        return JSONResponse(content=dataToSend)
    except:
        raise invalidCredentialsException


### --------------------------------
### ---------- NERU LOGIN ----------
### --------------------------------
# ref = db.reference("items")
# snapshot = ref.get(shallow=True)
# print(snapshot)

# ----- Log-in to NERU -----
# @app.post("/nerulogin", tags=["Login"], response_model=NeruLoginOut)
# def web_login(login: Login):
#     userData = loginUser(login.email, login.password)
    
#     if userData == None:
#         return JSONResponse(content={"error": "invalid credentials"}, status_code=400)
    
#     firestoreUserData = getUserDataByUID(userData["uid"])

#     if firestoreUserData["userType"] == UserTypes.admin:
#         ref = db.reference("items")
#         snapshot = ref.get(shallow=True)
        
#         sortedSites = sorted(snapshot.items())

# ----- Choose NERU location after logging in -----
# @app.put("/choosesite", tags=["Login"], response_model=SuccessfulOut)
# def choose_site(req=ChooseSite):
#     requestingUserUID = getUIDFromToken(req.token)
    # if requestingUserUID == None:
    #     return invalidTokenJSON
    
    # requestingUserData = getUserDataByUID(requestingUserUID)
    
    # if requestingUserData["userType"] == UserTypes.admin:
    #     ref = db.reference("items")
    #     snapshot = ref.get(shallow=True)
        
    #     sortedSites = sorted(snapshot.items())
        
    
    # return {}
