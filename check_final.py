from backend.db import db
print('CTIDigest:', db.ctidigest.count_documents({}))
print('Events:', db.events.count_documents({}))
print('Malware:', db.malware.count_documents({}))
print('Indicators:', db.indicators.count_documents({}))
