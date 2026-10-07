from backend.db import db
print('--- MISP Events by Source ---')
for res in db.events.aggregate([{'$group': {'_id': '$source', 'count': {'$sum': 1}}}]):
    print(res)
