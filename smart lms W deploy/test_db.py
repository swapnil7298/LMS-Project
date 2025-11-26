# test_db.py
import os
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

# Load the .env file
load_dotenv()

# Get the MONGO_URI from the environment
mongo_uri = os.getenv("MONGO_URI")

print("--- Database Connection Test ---")

if not mongo_uri:
    print("ERROR: MONGO_URI not found in .env file.")
else:
    print(f"Found MONGO_URI. Attempting to connect...")
    try:
        # Create a new client and connect to the server
        client = MongoClient(mongo_uri)
        
        # The ismaster command is cheap and does not require auth.
        client.admin.command('ismaster')
        
        print("\nSUCCESS: MongoDB connection established successfully!")
        print("Your .env file is working correctly.")
        
    except ConnectionFailure as e:
        print("\nERROR: Could not connect to MongoDB.")
        print("This is likely due to one of the following issues:")
        print("1. Incorrect password in your MONGO_URI.")
        print("2. The IP address of this computer is not whitelisted in MongoDB Atlas.")
        print("3. The free MongoDB cluster is paused.")
        print("\nDetails:", e)
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")

print("--- Test Complete ---")