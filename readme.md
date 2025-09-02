# FastAPI Task Management System

A comprehensive FastAPI example showcasing all important features of the framework.

## Features Demonstrated

1. **Basic FastAPI Setup**
2. **Pydantic Models & Validation**
3. **Authentication & Authorization (JWT)**
4. **CRUD Operations**
5. **Database Operations (In-memory)**
6. **Middleware (CORS)**
7. **Dependency Injection**
8. **Background Tasks**
9. **Exception Handling**
10. **Path & Query Parameters**
11. **Request Body Handling**
12. **Response Models**
13. **Status Codes**
14. **Tags & Documentation**
15. **Startup/Shutdown Events**

## Installation

```bash
pip install -r requirements.txt
```

## Running the Application

```bash
python main.py
# or
uvicorn main:app --reload
```

## API Documentation

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Sample Usage

1. Register: POST /auth/register
2. Login: POST /auth/login
3. Create tasks: POST /tasks
4. View tasks: GET /tasks
5. Update tasks: PUT /tasks/{id}

## Test Credentials

- Username: demo_user
- Password: demo123