
from utils import JWT
from sqlalchemy.exc import IntegrityError
from fastapi import FastAPI, Security, status, Response, Depends, Path, HTTPException, Request
from sqlalchemy.orm import Session
from fastapi.security import APIKeyHeader
from model import User, get_db
from schema import UserDetails, Userlogin
from passlib.hash import sha256_crypt
from settings import super_key
import requests as rq
from utils import jwt_authentication
app = FastAPI(title="End User")
admin_app = FastAPI(title="Admin or SuperUser",dependencies=[Security(APIKeyHeader(name='authorization')), Depends(jwt_authentication)])
jwt_handler = JWT()


@app.post("/register", status_code=status.HTTP_201_CREATED)
def user_registration(body: UserDetails, response: Response, db: Session = Depends(get_db)):
    """
    Description: This function create api for adding a new user.
    Parameter: body : UserDetails object, response : Response object, db : database session.
    Return: Message of user data added with status code 201.
    """
    try:
        user_data = body.model_dump()
        user_data['password'] = sha256_crypt.hash(user_data['password'])
        #if user has provided valid super key user is super user
        if user_data['super_key'] == super_key:
            user_data['is_super_user'] = True
        user_data.pop('super_key')
        new_user = User(**user_data)
        db.add(new_user)
        db.commit()
        
        token = jwt_handler.jwt_encode({'user_id': new_user.id})
        #using celery to send mail
        
        db.refresh(new_user)
        return {"status": 201, "message": "Registered successfully, check your mail to verify email", 'data': new_user, 'token' : token}
    except Exception as e:
        response.status_code = 400
        print(e)
        return {"message": str(e), 'status': 400}


@app.post("/login", status_code=status.HTTP_200_OK)
def user_login(payload: Userlogin, response: Response, db: Session = Depends(get_db)):
    """
    Description: This function create api for login the user.
    Parameter: payload : UserLogin object, response : Response object, db : database session.
    Return: Message of user logged in with status code 200.
    """
    try:
        user_data = db.query(User).filter_by(user_name=payload.user_name).first()
        if not user_data:
            raise HTTPException(detail="Invalid Username", status_code=status.HTTP_400_BAD_REQUEST)
        if not sha256_crypt.verify(payload.password, user_data.password) and user_data.is_verified:
            raise HTTPException(detail="Invalid Password", status_code=status.HTTP_400_BAD_REQUEST)
        if not user_data.is_verified:
            raise HTTPException(detail="Email is Not Verified", status_code=status.HTTP_400_BAD_REQUEST)
        token = JWT.jwt_encode({'user_id': user_data.id})
        return {'message': "Login successfully ", 'status': 200,'access_token':token}

        
    except Exception as e:
        response.status_code = 400
        return {"message": str(e), 'status': 400}
    
    
@app.get("/verify")
def verify_user(token: str, db: Session = Depends(get_db)):
    """
    Description: This function create api to verify the request when we click the verification link on send on mail.
    Parameter: token : object as string, db : as database session.
    Return: Message with status code 200 if verified done or 500 if internal server error
    """
    try:
        decode_token = JWT.jwt_decode(token)
        
        user_id = decode_token.get('user_id')
        user = db.query(User).filter_by(id=user_id, is_verified=False).one_or_none()
        if not user:
            raise HTTPException(status_code=400, detail='User already verified or not found')
        user.is_verified = True
        db.commit()
        return {'status': 200, "message": 'User verified successfully', }
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail='Internal Server Error')
    
    
@admin_app.post("/add_user", status_code=status.HTTP_201_CREATED)
def admin_add_user(request: Request, body: UserDetails, response: Response, db: Session = Depends(get_db)):
    """
    Description: This function create api for adding a new user by admin or a super user.
    Parameter: body : UserDetails object, response : Response object, db : database session.
    Return: Message of user data added with status code 201.
    """
    try:
        #Check whether a super user is trying to add a new user
        user_obj = db.query(User).filter_by(id=request.state.user.id).one_or_none()
        if user_obj and not user_obj.is_super_user:
            raise HTTPException(detail='Sorry You are Not a Super User', status_code=status.HTTP_400_BAD_REQUEST)
        if not user_obj:
            raise HTTPException(detail='You are not a valid user for this operation', status_code=status.HTTP_400_BAD_REQUEST)
        user_data = body.model_dump()
        user_data['password'] = sha256_crypt.hash(user_data['password'])
        #if admin wants the user to be a super user, they will give super key as 1 else it won't be a super user
        if user_data['super_key'] == '1':
            user_data['is_super_user'] = True
        else:
            user_data['is_super_user'] = False
        user_data.pop('super_key')
        #Since this user is added by the admin, it has to be a verified user
        user_data['is_verified'] = True
        new_user = User(**user_data)
        db.add(new_user)
        db.commit()
        
        token = jwt_handler.jwt_encode({'user_id': new_user.id})
        #using celery to send mail
        
        db.refresh(new_user)
        return {"status": 201, "message": "Registered successfully with verified", 'data': new_user, 'token' : token}
    except Exception as e:
        response.status_code = 400
        print(e)
        return {"message": str(e), 'status': 400}
