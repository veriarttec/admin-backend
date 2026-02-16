from database import SessionLocal
from sqlalchemy import text

db = SessionLocal()
result = db.execute(text("SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'banks' AND column_name = 'id'"))
print(list(result))
db.close()
