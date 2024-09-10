from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.security import OAuth2PasswordBearer
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from models import UserRegister, UserLogin, UserInDB
from utils.security import create_access_token, hash_password, verify_password, verify_token
from utils.db import *
from utils.logging import setup_logger
from utils.validators import *
from utils.exceptions import UserNotFoundException, InvalidCredentialsException
from utils.helpers import get_current_time
from starlette.exceptions import HTTPException as StarletteHTTPException

# Logger'ı ayarlıyoruz
logger = setup_logger()

app = FastAPI()

# Jinja2 template dizinini belirliyoruz
templates = Jinja2Templates(directory="templates")

# Statik dosyaları (CSS, JS) servis etmek için static dizini tanımlıyoruz
app.mount("/static", StaticFiles(directory="static"), name="static")

#db bağlanma
users_collection = get_users_collection()

# Token doğrulama işlevi için OAuth2PasswordBearer
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Ana sayfayı yükler
@app.get("/")
async def index(request: Request):
    return {"msg" : "This page is home page."}

# Kayıt olma sayfasını yükler
@app.get("/register", response_class=HTMLResponse)
async def get_register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


# Kayıt olma işlemi
@app.post("/register")
async def register(request: Request, username: str = Form(...), password: str = Form(...),email: str = Form(...)):
    # Kullanıcı adı olup olmadığını kontrol et
    username_existed = await is_username_existed(users_collection,username)
    if username_existed:
        return templates.TemplateResponse("register.html", {"request": request,"error" : "Bu kullanıcı adı sistemimizde kayıtlıdır."})
    
    
    # Kullanıcı maili mevcut olup olmadığını kontrol et
    email_existed = await is_email_existed(users_collection,email)
    if email_existed:
        return templates.TemplateResponse("register.html", {"request": request,"error" : "Bu mail sistemimizde kayıtlıdır."})
    
    #şifre uzunluk doğrulama
    password_valid = is_password_valid(password)
    if not password_valid:
        return templates.TemplateResponse("register.html", {"request": request,"error" : "Şifreniz 8-20 karakter uzunluğunda olmalıdır."})
    

    # Şifreyi hashleyip kullanıcıyı kaydetme
    hashed_password = hash_password(password)
    user_in_db = UserInDB(
        email=email,
        username=username,
        hashed_password=hashed_password
    )
    await users_collection.insert_one(user_in_db.dict())
    
    # Kayıt olma başarılıysa token oluştur
    access_token = create_access_token(data={"sub": username})
    
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(
        key="access_token", 
        value=f"Bearer {access_token}", 
        httponly=True, 
        max_age=18000 + 10800  # 300 dakika + 3 saat(utc'den dolayı) (saniye cinsinden)
    )
    
    logger.info(f"New user registered: {username} at {get_current_time()}")
    return response


# Giriş yapma sayfasını yükler
@app.get("/login", response_class=HTMLResponse)
async def get_login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


# Giriş yapma işlemi ve token oluşturma
@app.post("/login", response_class=HTMLResponse)
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    users_collection = get_users_collection()

    db_user = await users_collection.find_one({"username": username})
    if not db_user or not verify_password(password, db_user['hashed_password']):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Incorrect username or password"})

    # Giriş başarılıysa token oluştur
    access_token = create_access_token(data={"sub": username})
    
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(
        key="access_token", 
        value=f"Bearer {access_token}", 
        httponly=True, 
        max_age=18000 + 10800  # 300 dakika + 3 saat(utc'den dolayı) (saniye cinsinden)
    )
    
    logger.info(f"User {username} logged in at {get_current_time()}")
    return response

# Token doğrulama işlemi (korunan alanlar için)
def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if token is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    token = token.split(" ")[1]  # "Bearer <token>" şeklinde, sadece token kısmını al
    try:
        user = verify_token(token)
        return user
    except HTTPException:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

# Dashboard sayfası (korunan alan)
@app.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard(request: Request):
    try:
        user = get_current_user(request)
        print(user)
    except HTTPException:
        return RedirectResponse(url="/login")
    
    return templates.TemplateResponse("dashboard.html", {"request": request, "username": user})


# Logout işlemi
@app.post("/logout")
async def logout(request: Request):
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(key="access_token")
    return response





@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    # Hata kodunu ve hata türünü print ile kontrol edelim
    print(f"Handling exception with status code: {exc.status_code}")

    if exc.status_code == 401:
        return templates.TemplateResponse("401_error.html", {"request": request}, status_code=401)
    elif exc.status_code == 404:
        return templates.TemplateResponse("404_error.html", {"request": request}, status_code=404)
    elif exc.status_code == 500:
        return templates.TemplateResponse("500_error.html", {"request": request}, status_code=500)
    
    # Diğer durumlarda varsayılan hata işleyiciyi çağırıyoruz
    return JSONResponse(content={"detail": exc.detail,"status_code": exc.status_code}, status_code=exc.status_code)

