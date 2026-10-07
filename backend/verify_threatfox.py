from backend.db import indicators_collection


print("=" * 60)
print("THREATFOX DATABASE VERIFICATION")
print("=" * 60)


# ------------------------------------------------------------
# Count
# ------------------------------------------------------------

count = indicators_collection.count_documents(
    {"source": "ThreatFox"}
)

print("\nThreatFox document count:", count)


# ------------------------------------------------------------
# Sample
# ------------------------------------------------------------

sample = indicators_collection.find_one(
    {"source": "ThreatFox"}
)

print("\nSample document:")
print(sample)


# ------------------------------------------------------------
# Indexes
# ------------------------------------------------------------

print("\nIndexes:")

for index in indicators_collection.list_indexes():
    print(index)


# ------------------------------------------------------------
# IOC type distribution
# ------------------------------------------------------------

print("\nIOC type distribution:")

pipeline = [
    {
        "$match": {
            "source": "ThreatFox"
        }
    },
    {
        "$group": {
            "_id": "$type",
            "count": {"$sum": 1}
        }
    },
    {
        "$sort": {
            "count": -1
        }
    }
]

for result in indicators_collection.aggregate(pipeline):
    print(
        result["_id"],
        ":",
        result["count"]
    )


print("\nThreatFox verification completed.")