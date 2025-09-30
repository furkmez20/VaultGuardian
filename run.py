# run.py - Place this in the root directory
import sys
import os

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.app import app

if __name__ == '__main__':
    print("🔒 Starting Vault Guardian...")
    print("📂 Data will be stored in: data/vault.json")
    print("🌐 Access the app at: http://localhost:5000")
    print("🛑 Press Ctrl+C to stop the server")
    print("-" * 50)
    
    app.run(
        debug=True,
        host='127.0.0.1',
        port=5000
    )