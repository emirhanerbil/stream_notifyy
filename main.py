from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.security import OAuth2PasswordBearer
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from models import *
from utils.security import *
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
streamers_collection = get_streamers_collection()

# Token doğrulama işlevi için OAuth2PasswordBearer
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Ana sayfayı yükler
@app.get("/")
async def index(request: Request):
    return {"msg" : "This page is home page."}


# Kayıt olma sayfasını yükler
@app.get("/login-test", response_class=HTMLResponse)
async def login_test(request: Request):
    return templates.TemplateResponse("login_test.html", {"request": request})


# Kayıt olma işlemi
@app.post("/register")
async def register(request: Request, username: str = Form(...), password: str = Form(...),email: str = Form(...)):
    # Kullanıcı adı olup olmadığını kontrol et
    username_existed = await is_username_existed(users_collection,username)
    if username_existed:
        return templates.TemplateResponse("login_register.html", {"request": request,"error" : "Bu kullanıcı adı sistemimizde kayıtlıdır.","open_signup": True})
    
    # Kullanıcı maili mevcut olup olmadığını kontrol et
    email_existed = await is_email_existed(users_collection,email)
    if  email_existed:
        return templates.TemplateResponse("login_register.html", {"request": request,"error" : "Bu mail sistemimizde kayıtlıdır.","open_signup": True})
    
    #şifre uzunluk doğrulama
    password_valid = is_password_valid(password)
    if not password_valid:
        return templates.TemplateResponse("login_register.html", {"request": request,"error" : "Şifreniz 8-20 karakter uzunluğunda olmalıdır.","open_signup": True})
    
    # Şifreyi hashleyip kullanıcıyı kaydetme
    hashed_password = hash_password(password)
    user_in_db = UserInDB(
        email=email,
        username=username,
        hashed_password=hashed_password
    )
    await users_collection.insert_one(user_in_db.dict())
    
    streamer = Streamers(
        username=username,
        streamers = []
    )
    await streamers_collection.insert_one(streamer.dict())
    
    
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
    return templates.TemplateResponse("login_register.html", {"request": request})


# Giriş yapma işlemi ve token oluşturma
@app.post("/login", response_class=HTMLResponse)
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    users_collection = get_users_collection()

    db_user = await users_collection.find_one({"username": username})
    if not db_user or not verify_password(password, db_user['hashed_password']):
        return templates.TemplateResponse("login_register.html", {"request": request, "error": "Incorrect username or password"})

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
    except HTTPException:
        return RedirectResponse(url="/login")
    
    error = request.query_params.get("error")
    success = request.query_params.get("success")
    
    streamer_list = await get_streamers(user,streamers_collection)
    return templates.TemplateResponse("dashboard.html", {"request": request, "username": user,"streamers":streamer_list,"error":error,"success" : success})



@app.post("/delete_streamer/{streamer_name}", response_class=RedirectResponse)
async def delete_streamers(streamer_name: str, request: Request):
    user = get_current_user(request)  # Kullanıcı doğrulama
    # Streamer'ı veritabanından sil
    removed_streamer = await remove_streamer(user,streamers_collection,streamer_name)
    return RedirectResponse(url="/dashboard", status_code=303)

    
@app.post("/add_streamer",response_class=RedirectResponse)
async def add_streamers(streamer_name: str = Form(...), request: Request = Request):
    user = get_current_user(request)  # Kullanıcı doğrulama
    is_streamer_exist = await add_streamer(username=user,streamer_collection=streamers_collection,streamer_name=streamer_name)
    if is_streamer_exist:
        print(is_streamer_exist)
        return RedirectResponse(url="/dashboard?error=streamer_exists", status_code=303)
    
    return RedirectResponse(url="/dashboard?success=streamer_added", status_code=303)
    


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
    elif exc.status_code == 405:
        return templates.TemplateResponse("404_error.html", {"request": request}, status_code=405)
    elif exc.status_code == 500:
        return templates.TemplateResponse("500_error.html", {"request": request}, status_code=500)
    
    # Diğer durumlarda varsayılan hata işleyiciyi çağırıyoruz
    return JSONResponse(content={"detail": exc.detail,"status_code": exc.status_code}, status_code=exc.status_code)

