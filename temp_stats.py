from backend.db import db
print('Indicators by source:')
for res in db.indicators.aggregate([{'$group': {'_id': '$source', 'count': {'$sum': 1}}}]):
    print(res)
print('Malware by source:')
for res in db.malware.aggregate([{'$group': {'_id': '$source', 'count': {'$sum': 1}}}]):
    print(res)
