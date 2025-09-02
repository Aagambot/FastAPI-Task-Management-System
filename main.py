# FastAPI Task Management System
# A comprehensive example showcasing FastAPI's key features

from fastapi import FastAPI, HTTPException, Depends, status, Query, Path, Body, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from enum import Enum
import hashlib
import jwt
import uvicorn
import logging
from contextlib import asynccontextmanager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# JWT Configuration
SECRET_KEY = "your-secret-key-here"  # In production, use environment variable
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# In-memory databases (In production, use real databases)
users_db: Dict[str, Dict] = {}
tasks_db: Dict[str, Dict] = {}

# Enums
class TaskStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"

class Priority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

# Pydantic Models
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Username for the account")
    email: EmailStr = Field(..., description="Valid email address")
    password: str = Field(..., min_length=6, description="Password must be at least 6 characters")
    full_name: Optional[str] = Field(None, max_length=100, description="User's full name")

class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    full_name: Optional[str]
    created_at: datetime

class LoginRequest(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int

class TaskCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200, description="Task title")
    description: Optional[str] = Field(None, max_length=1000, description="Task description")
    priority: Priority = Field(default=Priority.MEDIUM, description="Task priority level")
    due_date: Optional[datetime] = Field(None, description="Due date for the task")

class TaskUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    status: Optional[TaskStatus] = None
    priority: Optional[Priority] = None
    due_date: Optional[datetime] = None

class TaskResponse(BaseModel):
    id: str
    title: str
    description: Optional[str]
    status: TaskStatus
    priority: Priority
    due_date: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    owner_id: str

# Startup/Shutdown events
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("🚀 FastAPI Task Management System starting up...")
    
    # Create sample data
    sample_user_id = create_sample_data()
    logger.info(f"✅ Sample data created with user ID: {sample_user_id}")
    
    yield
    
    # Shutdown
    logger.info("🛑 FastAPI Task Management System shutting down...")

# FastAPI app instance with lifespan events
app = FastAPI(
    title="Task Management API",
    description="A comprehensive FastAPI example with authentication, CRUD operations, and more",
    version="1.0.0",
    lifespan=lifespan
)

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Utility functions
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return hash_password(plain_password) == hashed_password

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_sample_data() -> str:
    """Create sample user and tasks for testing"""
    # Create sample user
    user_id = "user_123"
    users_db[user_id] = {
        "id": user_id,
        "username": "demo_user",
        "email": "demo@example.com",
        "password_hash": hash_password("demo123"),
        "full_name": "Demo User",
        "created_at": datetime.now()
    }
    
    # Create sample tasks
    sample_tasks = [
        {
            "id": "task_1",
            "title": "Complete FastAPI tutorial",
            "description": "Learn all FastAPI features",
            "status": TaskStatus.IN_PROGRESS,
            "priority": Priority.HIGH,
            "due_date": datetime.now() + timedelta(days=7),
            "created_at": datetime.now(),
            "updated_at": datetime.now(),
            "owner_id": user_id
        },
        {
            "id": "task_2", 
            "title": "Review code",
            "description": "Review pull requests",
            "status": TaskStatus.PENDING,
            "priority": Priority.MEDIUM,
            "due_date": None,
            "created_at": datetime.now(),
            "updated_at": datetime.now(),
            "owner_id": user_id
        }
    ]
    
    for task in sample_tasks:
        tasks_db[task["id"]] = task
    
    return user_id

# Dependency functions
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Extract and validate JWT token to get current user"""
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
            
        user = users_db.get(user_id)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
            
        return user
        
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

async def send_notification_email(email: str, subject: str, message: str):
    """Background task to send notification email"""
    # Simulate email sending
    logger.info(f"📧 Sending email to {email}: {subject} - {message}")
    # In real app, integrate with email service like SendGrid, AWS SES, etc.

# API Endpoints

@app.get("/", 
         summary="Root endpoint",
         description="Welcome message with API information")
async def root():
    """Root endpoint with API information"""
    return {
        "message": "Welcome to FastAPI Task Management System",
        "version": "1.0.0",
        "docs": "/docs",
        "endpoints": {
            "auth": "/auth/*",
            "tasks": "/tasks/*",
            "users": "/users/*"
        }
    }

# Health check endpoint
@app.get("/health", 
         tags=["Health"],
         summary="Health check")
async def health_check():
    """Simple health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now(),
        "users_count": len(users_db),
        "tasks_count": len(tasks_db)
    }

# Authentication endpoints
@app.post("/auth/register", 
          response_model=UserResponse,
          status_code=status.HTTP_201_CREATED,
          tags=["Authentication"],
          summary="Register new user")
async def register(user_data: UserCreate, background_tasks: BackgroundTasks):
    """Register a new user account"""
    # Check if user already exists
    for user in users_db.values():
        if user["username"] == user_data.username:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already exists"
            )
        if user["email"] == user_data.email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
    
    # Create new user
    user_id = f"user_{len(users_db) + 1}"
    new_user = {
        "id": user_id,
        "username": user_data.username,
        "email": user_data.email,
        "password_hash": hash_password(user_data.password),
        "full_name": user_data.full_name,
        "created_at": datetime.now()
    }
    
    users_db[user_id] = new_user
    
    # Send welcome email in background
    background_tasks.add_task(
        send_notification_email,
        user_data.email,
        "Welcome!",
        f"Welcome {user_data.username}! Your account has been created."
    )
    
    return UserResponse(**new_user)

@app.post("/auth/login", 
          response_model=Token,
          tags=["Authentication"],
          summary="Login user")
async def login(login_data: LoginRequest):
    """Authenticate user and return JWT token"""
    user = None
    for u in users_db.values():
        if u["username"] == login_data.username:
            user = u
            break
    
    if not user or not verify_password(login_data.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    access_token = create_access_token({"sub": user["id"]})
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

# User endpoints
@app.get("/users/me", 
         response_model=UserResponse,
         tags=["Users"],
         summary="Get current user profile")
async def get_current_user_profile(current_user: dict = Depends(get_current_user)):
    """Get current authenticated user's profile"""
    return UserResponse(**current_user)

# Task endpoints with various FastAPI features
@app.post("/tasks", 
          response_model=TaskResponse,
          status_code=status.HTTP_201_CREATED,
          tags=["Tasks"],
          summary="Create new task")
async def create_task(
    task_data: TaskCreate, 
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """Create a new task for the authenticated user"""
    task_id = f"task_{len(tasks_db) + 1}"
    new_task = {
        "id": task_id,
        "title": task_data.title,
        "description": task_data.description,
        "status": TaskStatus.PENDING,
        "priority": task_data.priority,
        "due_date": task_data.due_date,
        "created_at": datetime.now(),
        "updated_at": datetime.now(),
        "owner_id": current_user["id"]
    }
    
    tasks_db[task_id] = new_task
    
    # Send notification in background
    background_tasks.add_task(
        send_notification_email,
        current_user["email"],
        "New Task Created",
        f"Task '{task_data.title}' has been created successfully."
    )
    
    return TaskResponse(**new_task)

@app.get("/tasks", 
         response_model=List[TaskResponse],
         tags=["Tasks"],
         summary="Get user tasks with filtering")
async def get_tasks(
    current_user: dict = Depends(get_current_user),
    status: Optional[TaskStatus] = Query(None, description="Filter by task status"),
    priority: Optional[Priority] = Query(None, description="Filter by priority"),
    limit: int = Query(10, ge=1, le=100, description="Number of tasks to return"),
    skip: int = Query(0, ge=0, description="Number of tasks to skip")
):
    """Get user's tasks with optional filtering and pagination"""
    user_tasks = [
        task for task in tasks_db.values() 
        if task["owner_id"] == current_user["id"]
    ]
    
    # Apply filters
    if status:
        user_tasks = [task for task in user_tasks if task["status"] == status]
    if priority:
        user_tasks = [task for task in user_tasks if task["priority"] == priority]
    
    # Apply pagination
    user_tasks = user_tasks[skip:skip + limit]
    
    return [TaskResponse(**task) for task in user_tasks]

@app.get("/tasks/{task_id}", 
         response_model=TaskResponse,
         tags=["Tasks"],
         summary="Get specific task")
async def get_task(
    task_id: str = Path(..., description="The ID of the task to retrieve"),
    current_user: dict = Depends(get_current_user)
):
    """Get a specific task by ID"""
    task = tasks_db.get(task_id)
    
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found"
        )
    
    if task["owner_id"] != current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this task"
        )
    
    return TaskResponse(**task)

@app.put("/tasks/{task_id}", 
         response_model=TaskResponse,
         tags=["Tasks"],
         summary="Update task")
async def update_task(
    task_id: str = Path(..., description="The ID of the task to update"),
    task_update: TaskUpdate = Body(...),
    current_user: dict = Depends(get_current_user)
):
    """Update an existing task"""
    task = tasks_db.get(task_id)
    
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found"
        )
    
    if task["owner_id"] != current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this task"
        )
    
    # Update only provided fields
    update_data = task_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        task[field] = value
    
    task["updated_at"] = datetime.now()
    tasks_db[task_id] = task
    
    return TaskResponse(**task)

@app.delete("/tasks/{task_id}", 
            status_code=status.HTTP_204_NO_CONTENT,
            tags=["Tasks"],
            summary="Delete task")
async def delete_task(
    task_id: str = Path(..., description="The ID of the task to delete"),
    current_user: dict = Depends(get_current_user)
):
    """Delete a task"""
    task = tasks_db.get(task_id)
    
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found"
        )
    
    if task["owner_id"] != current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this task"
        )
    
    del tasks_db[task_id]

# Statistics endpoint demonstrating custom responses
@app.get("/tasks/stats", 
         tags=["Tasks"],
         summary="Get task statistics")
async def get_task_stats(current_user: dict = Depends(get_current_user)):
    """Get statistics about user's tasks"""
    user_tasks = [
        task for task in tasks_db.values() 
        if task["owner_id"] == current_user["id"]
    ]
    
    stats = {
        "total_tasks": len(user_tasks),
        "by_status": {},
        "by_priority": {},
        "overdue_tasks": 0
    }
    
    now = datetime.now()
    
    for task in user_tasks:
        # Count by status
        status = task["status"]
        stats["by_status"][status] = stats["by_status"].get(status, 0) + 1
        
        # Count by priority
        priority = task["priority"]
        stats["by_priority"][priority] = stats["by_priority"].get(priority, 0) + 1
        
        # Count overdue tasks
        if task["due_date"] and task["due_date"] < now and task["status"] != TaskStatus.COMPLETED:
            stats["overdue_tasks"] += 1
    
    return JSONResponse(content=stats)

# Exception handlers
@app.exception_handler(ValueError)
async def value_error_handler(request, exc):
    return JSONResponse(
        status_code=400,
        content={"detail": f"Value error: {str(exc)}"}
    )

if __name__ == "__main__":
    uvicorn.run(
        "main:app", 
        host="0.0.0.0", 
        port=8000, 
        reload=True,
        log_level="info"
    )