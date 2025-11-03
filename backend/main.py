from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlmodel import Field, SQLModel, Session, create_engine, select, delete

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------
SECRET_KEY = "dev-secret-change-me"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1 day

# -----------------------------------------------------------------------------
# DB (SQLite)
# -----------------------------------------------------------------------------
engine = create_engine("sqlite:///./app.db", echo=False)

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    password_hash: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

class Task(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(index=True, foreign_key="user.id")
    title: str
    description: Optional[str] = None
    due_date: Optional[str] = None  # YYYY-MM-DD
    status: str = Field(default="open")  # open | in_progress | done
    created_at: datetime = Field(default_factory=datetime.utcnow)

# extra tables already in your DB
class Tag(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(unique=True)

class TaskTag(SQLModel, table=True):
    task_id: int = Field(foreign_key="task.id", primary_key=True)
    tag_id: int = Field(foreign_key="tag.id", primary_key=True)

class Comment(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    task_id: int = Field(foreign_key="task.id")
    user_id: int = Field(foreign_key="user.id")
    body: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

def create_db():
    SQLModel.metadata.create_all(engine)

# -----------------------------------------------------------------------------
# Security helpers
# -----------------------------------------------------------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
def hash_password(pw: str) -> str: return pwd_context.hash(pw)
def verify_password(pw: str, pw_hash: str) -> bool: return pwd_context.verify(pw, pw_hash)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_db():
    with Session(engine) as session:
        yield session

# -----------------------------------------------------------------------------
# Schemas
# -----------------------------------------------------------------------------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class UserOut(BaseModel):
    id: int
    email: str

class RegisterBody(BaseModel):
    email: str
    password: str

class TaskIn(BaseModel):
    title: str
    description: Optional[str] = None
    due_date: Optional[str] = None
    status: Optional[str] = "open"
    tags: Optional[List[str]] = None   # NEW

class TaskOut(BaseModel):
    id: int
    title: str
    description: Optional[str]
    due_date: Optional[str]
    status: str
    created_at: datetime
    tags: List[str] = []               # NEW

# -----------------------------------------------------------------------------
# Auth dependency
# -----------------------------------------------------------------------------
def get_current_user(authorization: Optional[str] = Header(None),
                     db: Session = Depends(get_db)) -> User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.exec(select(User).where(User.email == email)).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# -----------------------------------------------------------------------------
# Tag helpers
# -----------------------------------------------------------------------------
def _norm(name: str) -> str:
    return name.strip().lower()

def _task_tags(db: Session, task_id: int) -> List[str]:
    rows = db.exec(
        select(Tag.name)
        .join(TaskTag, Tag.id == TaskTag.tag_id)
        .where(TaskTag.task_id == task_id)
    ).all()
    return list(rows or [])

def _ensure_tags(db: Session, names: List[str]) -> List[Tag]:
    """Create tags if missing. Returns Tag rows."""
    out: List[Tag] = []
    seen = set()
    for raw in names:
        n = _norm(raw)
        if not n or n in seen:
            continue
        seen.add(n)
        tag = db.exec(select(Tag).where(Tag.name == n)).first()
        if not tag:
            tag = Tag(name=n)
            db.add(tag)
            db.commit()
            db.refresh(tag)
        out.append(tag)
    return out

def _sync_task_tags(db: Session, task: Task, names: Optional[List[str]]):
    """Replace task's tag links with 'names'."""
    if names is None:
        return
    wanted = {_norm(n) for n in names if _norm(n)}
    # current tag ids
    current_links = db.exec(select(TaskTag).where(TaskTag.task_id == task.id)).all()
    current_tag_ids = {tt.tag_id for tt in current_links}
    # get/create desired tags
    desired_tags = _ensure_tags(db, list(wanted))
    desired_ids = {t.id for t in desired_tags}

    # delete unwanted links
    for tt in current_links:
        if tt.tag_id not in desired_ids:
            db.delete(tt)

    # add missing links
    for tag in desired_tags:
        if tag.id not in current_tag_ids:
            db.add(TaskTag(task_id=task.id, tag_id=tag.id))

    db.commit()

def _to_out(db: Session, t: Task) -> TaskOut:
    return TaskOut(
        id=t.id, title=t.title, description=t.description,
        due_date=t.due_date, status=t.status, created_at=t.created_at,
        tags=_task_tags(db, t.id)
    )

# -----------------------------------------------------------------------------
# App
# -----------------------------------------------------------------------------
app = FastAPI(title="QuickTasks API v4 (tags)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    create_db()

@app.get("/health")
def health():
    return {"ok": True}

# ---------------------- Auth ----------------------
@app.post("/auth/register", response_model=UserOut)
def register(body: RegisterBody, db: Session = Depends(get_db)):
    existing = db.exec(select(User).where(User.email == body.email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(email=body.email, password_hash=hash_password(body.password))
    db.add(user); db.commit(); db.refresh(user)
    return UserOut(id=user.id, email=user.email)

@app.post("/auth/login", response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.exec(select(User).where(User.email == form.username)).first()
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    token = create_access_token({"sub": user.email})
    return Token(access_token=token)

@app.get("/me", response_model=UserOut)
def me(current: User = Depends(get_current_user)):
    return UserOut(id=current.id, email=current.email)

# ---------------------- Tasks CRUD (+ tags) ----------------------
@app.get("/tasks", response_model=List[TaskOut])
def list_tasks(current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    tasks = db.exec(
        select(Task).where(Task.user_id == current.id).order_by(Task.created_at.desc())
    ).all()
    return [_to_out(db, t) for t in tasks]

@app.post("/tasks", response_model=TaskOut)
def create_task(body: TaskIn, current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    task = Task(user_id=current.id, title=body.title,
                description=body.description, due_date=body.due_date,
                status=body.status or "open")
    db.add(task); db.commit(); db.refresh(task)
    _sync_task_tags(db, task, body.tags or [])
    db.refresh(task)
    return _to_out(db, task)

@app.put("/tasks/{task_id}", response_model=TaskOut)
def update_task(task_id: int, body: TaskIn, current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    task = db.get(Task, task_id)
    if not task or task.user_id != current.id:
        raise HTTPException(status_code=404, detail="Task not found")
    if body.title is not None: task.title = body.title
    task.description = body.description
    task.due_date = body.due_date
    if body.status is not None: task.status = body.status
    db.add(task); db.commit(); db.refresh(task)
    _sync_task_tags(db, task, body.tags if body.tags is not None else None)
    return _to_out(db, task)

@app.delete("/tasks/{task_id}")
def delete_task(task_id: int, current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    task = db.get(Task, task_id)
    if not task or task.user_id != current.id:
        raise HTTPException(status_code=404, detail="Task not found")
    # remove tag links first (for cleanliness)
    db.exec(delete(TaskTag).where(TaskTag.task_id == task.id))
    db.delete(task); db.commit()
    return {"ok": True}

# ---------------------- Tags listing (for current user's tasks) ----------------------
@app.get("/tags", response_model=List[str])
def list_tags(current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.exec(
        select(Tag.name).join(TaskTag, Tag.id == TaskTag.tag_id).join(Task, Task.id == TaskTag.task_id)
        .where(Task.user_id == current.id)
    ).all()
    # unique + sorted
    names = sorted({r for r in rows})
    return names

# ---------------------- Demo seed ----------------------
@app.post("/seed")
def seed(current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    exists = db.exec(select(Task).where(Task.user_id == current.id)).first()
    if exists:
        return {"ok": True, "note": "User already has tasks; skipping seed."}
    samples = [
        ("Finish report", "in_progress", "2025-11-10", ["school", "urgent"]),
        ("Buy groceries", "open", None, ["home"]),
        ("Gym session", "done", "2025-11-01", ["health"]),
        ("Team meeting", "open", "2025-11-07", ["work"]),
        ("Fix bug #142", "in_progress", "2025-11-05", ["work", "urgent"]),
    ]
    for title, status, due, tags in samples:
        t = Task(user_id=current.id, title=title, status=status, due_date=due)
        db.add(t); db.commit(); db.refresh(t)
        _sync_task_tags(db, t, tags)
    return {"ok": True, "seeded": len(samples)}