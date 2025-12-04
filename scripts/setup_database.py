"""
Setup MySQL database and user for SecureChat.
Run this with root credentials to create database and user.

Usage: python scripts/setup_database.py
"""

import mysql.connector
from mysql.connector import Error


def setup_database():
    """Create database and user for SecureChat."""
    
    print("[*] SecureChat Database Setup")
    print("-" * 50)
    
    # Get root credentials
    root_password = input("Enter MySQL root password [default: rootpass]: ").strip() or "rootpass"
    
    try:
        # Connect as root
        print("[*] Connecting to MySQL as root...")
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password=root_password
        )
        
        if connection.is_connected():
            print("[✓] Connected to MySQL server")
            cursor = connection.cursor()
            
            # Create database
            print("[*] Creating database 'securechat'...")
            cursor.execute("CREATE DATABASE IF NOT EXISTS securechat")
            print("[✓] Database 'securechat' ready")
            
            # Create user (drop if exists first)
            print("[*] Setting up user 'scuser'...")
            try:
                # Drop user if exists
                cursor.execute("DROP USER IF EXISTS 'scuser'@'localhost'")
                # Create fresh user
                cursor.execute("CREATE USER 'scuser'@'localhost' IDENTIFIED BY 'scpass'")
                print("[✓] User 'scuser' created")
            except Error as e:
                print(f"[!] User setup warning: {e}")
                # Continue anyway - might already exist with correct password
            
            # Grant privileges
            print("[*] Granting privileges...")
            cursor.execute("GRANT ALL PRIVILEGES ON securechat.* TO 'scuser'@'localhost'")
            cursor.execute("FLUSH PRIVILEGES")
            print("[✓] Privileges granted")
            
            print("\n" + "=" * 50)
            print("[✓] Database setup complete!")
            print("=" * 50)
            print("\nConfiguration:")
            print("  Database: securechat")
            print("  User: scuser")
            print("  Password: scpass")
            print("  Host: localhost")
            print("  Port: 3306")
            print("\nUpdate your .env file with these settings.")
            
    except Error as e:
        print(f"\n[✗] Database setup failed: {e}")
        print("\nTroubleshooting:")
        print("  1. Make sure MySQL is running")
        print("  2. Check root password")
        print("  3. Try running: mysql -u root -p")
        return False
    
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
            print("\n[✓] Connection closed")
    
    return True


if __name__ == "__main__":
    setup_database()