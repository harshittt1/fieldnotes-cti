from backend.db import client, db


try:
    client.admin.command("ping")

    print("MongoDB Atlas connection successful!")
    print("Database:", db.name)

    print("\nCollections:")
    print(db.list_collection_names())

except Exception as e:
    print("MongoDB connection failed:")
    print(e)

finally:
    client.close()