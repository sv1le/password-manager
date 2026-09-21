from pymongo import MongoClient
import os
from dotenv import load_dotenv

# Load .env file
load_dotenv()

# Get connection string from .env
uri = os.getenv('MONGO_URI')

print("🔍 Testing MongoDB connection...")
print(f"📡 Using URI: {uri[:40]}...")

try:
    # Connect to MongoDB
    client = MongoClient(uri)
    
    # Get database
    db = client['password_manager']
    
    # Test by inserting a test document
    test_collection = db['test']
    result = test_collection.insert_one({'test': 'connection_working'})
    
    print("✅ SUCCESS! Connected to MongoDB Atlas!")
    print(f"✅ Test document ID: {result.inserted_id}")
    
    # Clean up
    test_collection.delete_one({'_id': result.inserted_id})
    print("✅ Test document deleted. Database is ready!")
    
    # Show available databases
    print("\n📊 Available databases:")
    for db_name in client.list_database_names():
        print(f"   - {db_name}")
    
except Exception as e:
    print("❌ ERROR: Could not connect to MongoDB")
    print(f"❌ Error: {e}")