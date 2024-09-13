from datetime import datetime
import smtplib

from fastapi import HTTPException, Request

from utils.security import verify_token

def get_current_time():
    return datetime.utcnow()

def object_id_to_str(obj_id):
    return str(obj_id)


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
    
    
    
# Doğrulama kodu gönderme fonksiyonu
def send_email_verification_code(email: str, verification_code: int):
    # SMTP ayarları ile e-posta gönderme işlemi
    with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
        smtp.starttls()
        smtp.login('emirhan117net@gmail.com', 'snzc smap wtqx foky')
        message = f'Subject: Email Verification\n\nYour verification code is {verification_code}'
        smtp.sendmail('emirhan117net@gmail.com', email, message)
