from enum import Enum
from typing import List, Optional, TypedDict, Dict
from pydantic import BaseModel, Field

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
    
class UserEdit(GetData):
    uid: str = Field(..., example="5dci23SoQXQIRQgXVwacYGNrrWS2")
    email: Optional[str] = Field(None, example="user@email.com")
    password: Optional[str] = Field(None, example="password123")
    userType: Optional[UserTypes] = Field(None, example=UserTypes.site_manager)
    addSites: Optional[List[str]] = Field([], example=["Birmingham, London"])
    delSites: Optional[List[str]] = Field([], example=["Newcastle", "Battersea"])
    
class UserCreate(UserBase):
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
    