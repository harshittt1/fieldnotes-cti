from backend.db import db


print("Database:", db.name)

print("\nCollections:")
print(db.list_collection_names())


for collection_name in db.list_collection_names():
    collection = db[collection_name]

    print("\n" + "=" * 50)
    print("COLLECTION:", collection_name)
    print("=" * 50)

    print("Document count:", collection.count_documents({}))

    sample = collection.find_one()

    if sample:
        print("\nSample document:")
        print(sample)
    else:
        print("Collection is empty.")