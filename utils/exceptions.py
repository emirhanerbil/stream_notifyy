from fastapi import HTTPException

class UserNotFoundException(HTTPException):
    def __init__(self):
        super().__init__(status_code=404, detail="User not found")

class InvalidCredentialsException(HTTPException):
    def __init__(self):
        super().__init__(status_code=400, detail="Incorrect username or password")
