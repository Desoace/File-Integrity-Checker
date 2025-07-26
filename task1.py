#!/usr/bin/env python3
"""
File Integrity Checker
A tool to monitor file changes by calculating and comparing hash values.
Author: CODTECH Intern
"""

import hashlib
import os
import json
import argparse
from datetime import datetime
from pathlib import Path


class FileIntegrityChecker:
    def __init__(self, database_file="file_hashes.json"):
        """Initialize the File Integrity Checker with a database file."""
        self.database_file = database_file
        self.file_hashes = self.load_database()
    
    def load_database(self):
        """Load existing hash database from JSON file."""
        if os.path.exists(self.database_file):
            try:
                with open(self.database_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                print(f"Warning: Could not read {self.database_file}. Starting with empty database.")
                return {}
        return {}
    
    def save_database(self):
        """Save hash database to JSON file."""
        with open(self.database_file, 'w') as f:
            json.dump(self.file_hashes, f, indent=4)
    
    def calculate_hash(self, filepath, algorithm='sha256'):
        """
        Calculate hash of a file using specified algorithm.
        Supports: md5, sha1, sha256, sha512
        """
        hash_algorithms = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256(),
            'sha512': hashlib.sha512()
        }
        
        if algorithm not in hash_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        hasher = hash_algorithms[algorithm]
        
        try:
            with open(filepath, 'rb') as f:
                # Read file in chunks to handle large files efficiently
                for chunk in iter(lambda: f.read(4096), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except FileNotFoundError:
            return None
        except PermissionError:
            print(f"Permission denied: {filepath}")
            return None
    
    def add_file(self, filepath, algorithm='sha256'):
        """Add a file to the integrity monitoring system."""
        filepath = os.path.abspath(filepath)
        
        if not os.path.exists(filepath):
            print(f"Error: File '{filepath}' does not exist.")
            return False
        
        file_hash = self.calculate_hash(filepath, algorithm)
        if file_hash:
            self.file_hashes[filepath] = {
                'hash': file_hash,
                'algorithm': algorithm,
                'last_checked': datetime.now().isoformat(),
                'added_on': datetime.now().isoformat() if filepath not in self.file_hashes else self.file_hashes[filepath].get('added_on', datetime.now().isoformat())
            }
            self.save_database()
            print(f"✓ Added file: {filepath}")
            print(f"  Hash ({algorithm}): {file_hash}")
            return True
        return False
    
    def check_file(self, filepath):
        """Check if a file has been modified since last check."""
        filepath = os.path.abspath(filepath)
        
        if filepath not in self.file_hashes:
            print(f"File '{filepath}' is not being monitored.")
            return None
        
        if not os.path.exists(filepath):
            print(f"⚠ WARNING: File '{filepath}' has been deleted!")
            return False
        
        stored_data = self.file_hashes[filepath]
        current_hash = self.calculate_hash(filepath, stored_data['algorithm'])
        
        if current_hash == stored_data['hash']:
            print(f"✓ File intact: {filepath}")
            return True
        else:
            print(f"⚠ WARNING: File modified: {filepath}")
            print(f"  Expected hash: {stored_data['hash']}")
            print(f"  Current hash:  {current_hash}")
            return False
    
    def check_all(self):
        """Check all monitored files for changes."""
        print(f"\n{'='*60}")
        print(f"File Integrity Check Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")
        
        total_files = len(self.file_hashes)
        intact_files = 0
        modified_files = 0
        deleted_files = 0
        
        for filepath in self.file_hashes:
            result = self.check_file(filepath)
            if result is True:
                intact_files += 1
            elif result is False:
                if os.path.exists(filepath):
                    modified_files += 1
                else:
                    deleted_files += 1
            print()
        
        print(f"{'='*60}")
        print(f"Summary:")
        print(f"  Total files monitored: {total_files}")
        print(f"  Files intact: {intact_files}")
        print(f"  Files modified: {modified_files}")
        print(f"  Files deleted: {deleted_files}")
        print(f"{'='*60}\n")
    
    def remove_file(self, filepath):
        """Remove a file from monitoring."""
        filepath = os.path.abspath(filepath)
        
        if filepath in self.file_hashes:
            del self.file_hashes[filepath]
            self.save_database()
            print(f"✓ Removed file from monitoring: {filepath}")
            return True
        else:
            print(f"File '{filepath}' is not being monitored.")
            return False
    
    def list_files(self):
        """List all monitored files."""
        if not self.file_hashes:
            print("No files are currently being monitored.")
            return
        
        print(f"\n{'='*60}")
        print("Monitored Files:")
        print(f"{'='*60}\n")
        
        for filepath, data in self.file_hashes.items():
            print(f"File: {filepath}")
            print(f"  Algorithm: {data['algorithm']}")
            print(f"  Hash: {data['hash']}")
            print(f"  Added: {data.get('added_on', 'Unknown')}")
            print(f"  Last checked: {data['last_checked']}")
            print()
    
    def update_hash(self, filepath):
        """Update the stored hash for a file (after legitimate modification)."""
        filepath = os.path.abspath(filepath)
        
        if filepath not in self.file_hashes:
            print(f"File '{filepath}' is not being monitored.")
            return False
        
        if not os.path.exists(filepath):
            print(f"Error: File '{filepath}' does not exist.")
            return False
        
        algorithm = self.file_hashes[filepath]['algorithm']
        new_hash = self.calculate_hash(filepath, algorithm)
        
        if new_hash:
            old_hash = self.file_hashes[filepath]['hash']
            self.file_hashes[filepath]['hash'] = new_hash
            self.file_hashes[filepath]['last_checked'] = datetime.now().isoformat()
            self.save_database()
            print(f"✓ Updated hash for file: {filepath}")
            print(f"  Old hash: {old_hash}")
            print(f"  New hash: {new_hash}")
            return True
        return False


def main():
    parser = argparse.ArgumentParser(
        description="File Integrity Checker - Monitor file changes using hash values",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python file_integrity_checker.py add file.txt
  python file_integrity_checker.py add file.txt --algorithm sha512
  python file_integrity_checker.py check file.txt
  python file_integrity_checker.py check-all
  python file_integrity_checker.py update file.txt
  python file_integrity_checker.py remove file.txt
  python file_integrity_checker.py list
        """
    )
    
    parser.add_argument('action', choices=['add', 'check', 'check-all', 'update', 'remove', 'list'],
                       help='Action to perform')
    parser.add_argument('file', nargs='?', help='File path (not required for check-all and list)')
    parser.add_argument('--algorithm', choices=['md5', 'sha1', 'sha256', 'sha512'], 
                       default='sha256', help='Hash algorithm to use (default: sha256)')
    parser.add_argument('--database', default='file_hashes.json',
                       help='Database file to store hashes (default: file_hashes.json)')
    
    args = parser.parse_args()
    
    # Initialize the checker
    checker = FileIntegrityChecker(args.database)
    
    # Perform the requested action
    if args.action == 'add':
        if not args.file:
            print("Error: File path required for 'add' action")
            return
        checker.add_file(args.file, args.algorithm)
    
    elif args.action == 'check':
        if not args.file:
            print("Error: File path required for 'check' action")
            return
        checker.check_file(args.file)
    
    elif args.action == 'check-all':
        checker.check_all()
    
    elif args.action == 'update':
        if not args.file:
            print("Error: File path required for 'update' action")
            return
        checker.update_hash(args.file)
    
    elif args.action == 'remove':
        if not args.file:
            print("Error: File path required for 'remove' action")
            return
        checker.remove_file(args.file)
    
    elif args.action == 'list':
        checker.list_files()


if __name__ == "__main__":
    main()