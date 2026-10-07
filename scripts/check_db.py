import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv('backend/.env')
uri = os.getenv('MONGODB_URI')
db = MongoClient(uri).cti_database

print('Total events:', db.events.count_documents({}))
print('Sources in DB:')
for s in db.events.distinct('source'):
    print(f'- {s}: {db.events.count_documents({"source": s})}')
