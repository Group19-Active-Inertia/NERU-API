from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import firebase_admin
from firebase_admin import credentials, auth, db, firestore
import requests
import boto3
from coapthon.client.helperclient import HelperClient

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

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/", include_in_schema=False)
def welcomePage():
    return {"API Works!":"Welcome!"}


# ----- Firebase admin client -----
cred = credentials.Certificate("key.json")

firebase_admin.initialize_app(
    cred, 
    {'databaseURL': "https://create-active-inertia-default-rtdb.europe-west1.firebasedatabase.app",
     'projectId': "create-active-inertia",
     }
    )

fs = firestore.client()
table = fs.collection('users')


# ----- AWS admin client -----
aws_access_key_id = "AKIARD43YVXRS2TCFVIQ"
aws_secret_access_key = "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"

client = boto3.client(
    'iot', 
    region_name="eu-west-2", 
    aws_access_key_id=aws_access_key_id, 
    aws_secret_access_key=aws_secret_access_key
    )

#### ---------------------------------
#### -------- COMMON CLASSES ---------
#### ---------------------------------

class UserTypes(str, Enum):
    admin = "admin"
    site_manager = "sitemanager"
    default_user = "default"
    
class LoginOut(BaseModel):
    sites: List[str] = Field(..., example=["Birmingham", "London", "Newcastle"])
    idToken: str = Field(..., example="q2uWM7esugFJhGptPtIItpF8OWxS6vr2CrQ1cMH81ZoXmQ........")
    refreshToken: str = Field(..., example="AGEhc0AijkK9xYrO3Iams2II8EQJr-uwncfej4amfxT-........")
    tokenExpiresIn: str = Field(..., example="3600")

class GetData(BaseModel):
    token: str = Field(..., example="q2uWM7esugFJhGptPtIItpF8OWxS6vr2CrQ1cMH81ZoXmQ........")
    
#### --------------------------------
#### -------- INPUT CLASSES ---------
#### --------------------------------
    
class GetUserData(GetData):
    uid: Optional[str] = Field(None, example="5dci23SoQXQIRQgXVwacYGNrrWS2")
    
class DelUserData(GetData):
    uid: str = Field(..., example="5dci23SoQXQIRQgXVwacYGNrrWS2")
    
class UserEdit(GetData):
    uid: str = Field(..., example="5dci23SoQXQIRQgXVwacYGNrrWS2")
    email: Optional[str] = Field(None, example="user@email.com")
    password: Optional[str] = Field(None, example="password123")
    userType: Optional[UserTypes] = Field(None, example=UserTypes.site_manager)
    addSites: Optional[List[str]] = Field([], example=["Birmingham, London"])
    delSites: Optional[List[str]] = Field([], example=["Newcastle", "Battersea"])
    
class UserCreate(GetData):
    email: str = Field(..., example="user@email.com")
    password: Optional[str] = Field(None, example="password123")
    sites: List[str] = Field([], example=["Birmingham", "London", "Newcastle"])
    userType: Optional[UserTypes] = Field(UserTypes.default_user, example=UserTypes.site_manager)
    
class AddSite(GetData):
    name: str = Field(..., example="Birmingham")
    port: Optional[int] = Field(None, example=5863)

class DeleteSite(GetData):
    name: str = Field(..., example="Birmingham")

class Login(BaseModel):
    email: str = Field(..., example="user@email.com")
    password: str = Field(..., example="password123")
    
class ChooseSite(GetData):
    site: str = Field(..., example="Nottingham")
    lat: float = Field(..., example=51.01233)
    lon: float = Field(..., example=-1.25123)
    ip: str = Field(..., example="123.123.123.123")
    
class EditSite(GetData):
    site: str = Field(..., example="Nottingham")
    newSite: Optional[str] = Field(None, example="Nottingham North")
    newPort: Optional[int] = Field(None, example=8080)

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

class WebLoginOut(LoginOut):
    uid: str = Field(None, example="5dci23SoQXQIRQgXVwacYGNrrWS2")
    userType: UserTypes = Field(..., example=UserTypes.site_manager)

class SuccessfulOut(BaseModel):
    response: str = Field("successful request", example="successful request")
    
class AddUserOut(BaseModel):
    uid: str = Field(..., example="5dci23SoQXQIRQgXVwacYGNrrWS2")
    
    
### ----------------------------------------
### ----------- HELPER FUNCTIONS -----------
### ----------------------------------------

# takes two lists
# returns list of common values
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


def getSiteData(site: str):
    return db.reference("nerus").child(site).get()

### -----------------------------------------
### ----------- HANDLER FUNCTIONS -----------
### -----------------------------------------

def createUser(user: UserCreate):
    if (user.email == None or
        user.password == None):
        return None
        
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

def addSitesToUser(uid: str, sites: List[str]):
    ref = table.document(uid)
    ref.update({u'sites': firestore.ArrayUnion(sites)})
    return

def removeSitesFromUser(uid: str, sites: List[str]):
    ref = table.document(uid)
    ref.update({u'sites': firestore.ArrayRemove(sites)})
    return

def editUser(user: UserEdit):
    batch = fs.batch()
    ref = table.document(user.uid)
    
    try:
        # returns error if email is not found
        auth.get_user_by_email(user.email)
        return False
    except:
        pass
    
    firestoreUpdates = {}
    
    if user.email != None and user.password != None:
        auth.update_user(user.uid, email=user.email, password=user.password)
        firestoreUpdates["email":user.email]
        
    elif user.email != None:
        auth.update_user(user.uid, email=user.email)
        firestoreUpdates["email":user.email]
        
    elif user.password != None:
        auth.update_user(user.uid, password=user.password)
        
    if user.userType != None:
        firestoreUpdates["userType":user.userType]

    batch.update(ref, firestoreUpdates)
        
    batch.commit()
    
    addSitesToUser(user.uid, user.addSites)
    removeSitesFromUser(user.uid, user.delSites)
    
    return True    

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

def createNewThingAndKeys(name: str):
    try:
        principals = client.list_thing_principals(thingName=name)
        print(principals)
        for principal in principals["principals"]:
            client.detach_thing_principal(
                thingName=name,
                principal=principal
            )
            
    except:
        client.create_thing(thingName=name)
    
    createKeysResponse = client.create_keys_and_certificate(setAsActive=True)
    
    client.attach_thing_principal(
        thingName=name,
        principal=createKeysResponse["certificateArn"]
    )
    
    return {
        "certificatePem": createKeysResponse["certificatePem"],
        "publicKey": createKeysResponse["keyPair"]["PublicKey"],
        "privateKey": createKeysResponse["keyPair"]["PrivateKey"],
    }


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
        raise invalidTokenException
    
    requestingUserData = getUserDataByUID(requestingUserUID)[requestingUserUID]

    if requestingUserData["userType"] == UserTypes.default_user:
        raise unauthorizedException
    
    # return user uid and data
    if uid != None:
        queriedUser = getUserDataByUID(uid)
        
        if queriedUser == None:
            raise HTTPException(400, {"error": "queried uid does not exist."})
        
        elif requestingUserData["userType"] == UserTypes.admin:
            return JSONResponse(queryToDict(queriedUser))
        
        elif requestingUserData["userType"] == UserTypes.site_manager:
            if len(intersect(requestingUserData["sites"], queriedUser[uid]["sites"])) > 0:
                return JSONResponse(queryToDict(queriedUser))
            
            raise unauthorizedException
    
    #return all accounts which user has permission for
    else:
        if requestingUserData["userType"] == UserTypes.admin:
            allUsers = table.get()
            return JSONResponse(queryToDict(allUsers))
        
        elif requestingUserData["userType"] == UserTypes.site_manager:
            return JSONResponse(content=getUsersBySites(requestingUserData["sites"]))
        
    # if all above fails
    raise invalidDataException

# ----- Removing user -----
@app.delete("/accounts", tags=["User Management"], response_model=SuccessfulOut)
def delete_user(delUser: DelUserData):
    
    def deleteUserFromFirebase(uid):
        table.document(uid).delete()
        auth.delete_user(uid)
        
    requestingUserUID = getUIDFromToken(delUser.token)
    if requestingUserUID == None:
        raise invalidTokenException
    
    requestingUserData = getUserDataByUID(requestingUserUID)[requestingUserUID]
    
    if requestingUserData["userType"] == UserTypes.admin:
        deleteUserFromFirebase(delUser.uid)
        return successfulJSON
    
    if requestingUserData["userType"] == UserTypes.site_manager:
        userToDelete = getUserDataByUID(delUser.uid)
        commonSites = intersect(requestingUserData["sites"], userToDelete["sites"])
        
        if len(commonSites) == len(userToDelete["sites"]):
            deleteUserFromFirebase(delUser.uid)
            return successfulJSON
        
        else:
            removeSitesFromUser(delUser.uid, requestingUserData["sites"])
            return successfulJSON
        
    raise unauthorizedException

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
        
        # try if user already exists
        try:
            uid = addSitesOnly()
         
        # if user doesnt exist
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
        if editUser(user):
            return successfulJSON
        return HTTPException(400, {"error": "email already exists"})
    
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
@app.post("/site", tags=["Site Management"], response_model=SuccessfulOut)
def add_site(site: AddSite):
    requestingUserUID = getUIDFromToken(site.token)
    if requestingUserUID == None:
        raise invalidTokenException
    
    requestingUserData = getUserDataByUID(requestingUserUID)[requestingUserUID]
    
    if requestingUserData["userType"] == UserTypes.admin:
        ref = db.reference("nerus").child(site.name)
        
        if ref.get() == None:
            ref.set({
                "Name": site.name,
                "Port": site.port
                })
            
        else:
            raise HTTPException(400, {"error": "site already exists"})
        
        return successfulJSON
    
    raise unauthorizedException
    

# # ----- Delete site from database -----
@app.delete("/site", tags=["Site Management"], response_model=SuccessfulOut)
def delete_site(site: DeleteSite):
    requestingUserUID = getUIDFromToken(site.token)
    if requestingUserUID == None:
        raise invalidTokenException
    
    requestingUserData = getUserDataByUID(requestingUserUID)[requestingUserUID]
    
    if requestingUserData["userType"] == UserTypes.admin:
        ref = db.reference("nerus").child(site.name)
        
        # remove sites from firestore users
        if ref.get() != None:
            users = getUsersBySites([site.name])
            
            batch = fs.batch()
            
            for uid, data in users.items():
                userRef = table.document(uid)
                
                batch.update(userRef, {u'sites': firestore.ArrayRemove([site.name])})
                
            batch.commit()
            
        else:
            raise HTTPException(400, {"error": "site does not exist"})
        
        # delete thing on aws
        try:
            client.delete_thing(thingName=site.name)
        except:
            pass
        
        return successfulJSON
    
    raise unauthorizedException

# # ----- Edit site data -----
@app.put("/site", tags=["Site Management"], response_model=SuccessfulOut)
def edit_site(site: EditSite):
    requestingUserUID = getUIDFromToken(site.token)
    if requestingUserUID == None:
        raise invalidTokenException
    
    requestingUserData = getUserDataByUID(requestingUserUID)[requestingUserUID]
    
    if requestingUserData["userType"] == UserTypes.admin:
        oldSiteRef = db.reference("nerus").child(site.site)
        newSiteRef = db.reference("nerus").child(site.newSite)
        
        oldSiteData = oldSiteRef.get()
        
        if oldSiteData == None:
            raise HTTPException(400, {"error": "site does not exist"})
        
        elif (site.newSite != None and 
            oldSiteData != None and 
            newSiteRef.get() == None
            ):
            
            # update firestore database
            users = getUsersBySites([site.site])
            
            batch = fs.batch()
            
            for uid, data in users.items():
                userRef = table.document(uid)
                
                newSites = [site.newSite if name == site.site else name for name in data["sites"]]
                
                batch.update(userRef, {"sites": newSites})
                
            batch.commit()
            
            # update realtime database
            newSiteData = oldSiteData.copy()
            if site.newPort != None:
                newSiteData["Port"] = site.newPort
            newSiteData["Name"] = site.newSite
            newSiteRef.set(newSiteData)
            oldSiteRef.delete()
            
            return successfulJSON
            
        elif site.newSite == None and site.newPort != None:
            oldSiteRef.update({"Port": site.newPort})
            return successfulJSON
        
        return successfulJSON
    
    raise unauthorizedException

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

# ----- Log-in to NERU -----
@app.post("/nerulogin", tags=["Login"], response_model=LoginOut)
def neru_login(login: Login):
    userData = loginUser(login.email, login.password)
    
    if userData == None:
        raise invalidCredentialsException
    
    firestoreUserData = getUserDataByUID(userData["uid"])[userData]

    if firestoreUserData["userType"] == UserTypes.admin:
        ref = db.reference("nerus")
        snapshot = ref.get(shallow=True)
        
        sortedSites = sorted(snapshot.items())
        
    else:
        sortedSites = sorted(firestoreUserData["sites"])
        
    responseContent = {
        "idToken": userData["idToken"],
        "refreshToken": userData["refreshToken"],
        "tokenExpiresIn": userData["tokenExpiresIn"],
        "sites": sortedSites
    }
    
    return JSONResponse(content=responseContent)

# ----- Choose NERU location after logging in -----
@app.post("/choosesite", tags=["Login"], response_model=SuccessfulOut)
def choose_site(site: ChooseSite):
    
    siteData = getSiteData(site.site)
    
    if siteData == None:
        raise invalidDataException
    
    def testCoAP():
        try:
            client = HelperClient(server=(site.ip, siteData["Port"]))
            response = client.get('test', timeout=1)
            client.stop()
            
            if response:
                return True
            
        except:
            pass
        
        return False
    
    def updateNERUOnFirebase():
        ref = db.reference(f"nerus/{site.site}")
        newData = {
            "CurrentIP": site.ip,
            "Latitude": site.lat,
            "Longitude": site.lon,
            "Online": True,
        }
        ref.update(newData)
    
    def approveConnection():
        updateNERUOnFirebase()
        data = createNewThingAndKeys(site.site)
        return JSONResponse(content=data)

    requestingUserUID = getUIDFromToken(site.token)
    if requestingUserUID == None:
        raise invalidTokenException
    
    requestingUserData = getUserDataByUID(requestingUserUID)
    
    if testCoAP():
        if requestingUserData["userType"] == UserTypes.admin:
            return approveConnection()
            
        else:
            userData = getUserDataByUID(requestingUserUID)
            
            if site.site in userData["sites"]:
                return approveConnection()
    
    else:
        raise HTTPException(400, {"error":"CoAP server did not return a response"})
            
    raise invalidDataException
    