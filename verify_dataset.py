from backend.db import db
from pprint import pprint

print('--- DATASET COUNTS ---')
print('Events:', db.events.count_documents({}))
print('Indicators:', db.indicators.count_documents({}))

print('\n--- GALAXY ENRICHMENT VERIFICATION ---')
print('Top 5 Threat Actors/Tools found in events:')
pipeline = [
    {'$unwind': '$galaxy_clusters'}, 
    {'$group': {'_id': '$galaxy_clusters', 'count': {'$sum': 1}}}, 
    {'$sort': {'count': -1}}, 
    {'$limit': 5}
]
for res in db.events.aggregate(pipeline):
    print(res)

print('\n--- SAMPLE ENRICHED EVENT ---')
sample = db.events.find_one({'galaxy_clusters': {'$exists': True, '$ne': []}}, {'_id': 0, 'raw_data': 0})
if sample:
    pprint(sample)
else:
    print("No enriched events found yet.")
