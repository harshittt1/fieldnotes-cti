from backend.db import ctidigest_collection


print("=" * 60)
print("CTIDIGEST DATABASE VERIFICATION")
print("=" * 60)


# ------------------------------------------------------------
# Document count
# ------------------------------------------------------------

count = ctidigest_collection.count_documents({})

print("\nDocument count:", count)


# ------------------------------------------------------------
# Sample document
# ------------------------------------------------------------

sample = ctidigest_collection.find_one()

print("\nSample document:")
print(sample)


# ------------------------------------------------------------
# Indexes
# ------------------------------------------------------------

print("\nIndexes:")

for index in ctidigest_collection.list_indexes():
    print(index)


# ------------------------------------------------------------
# Source distribution
# ------------------------------------------------------------

print("\nSource distribution:")

pipeline = [
    {
        "$group": {
            "_id": "$source_name",
            "count": {"$sum": 1}
        }
    },
    {
        "$sort": {
            "count": -1
        }
    }
]

for result in ctidigest_collection.aggregate(pipeline):
    print(
        result["_id"],
        ":",
        result["count"]
    )


print("\nVerification completed.")