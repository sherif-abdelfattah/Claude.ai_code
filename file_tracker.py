# requirements.txt
"""
Flask==2.3.3
pymongo==4.5.0
python-dotenv==1.0.0
"""

# app.py
"""
from flask import Flask, request, jsonify, render_template
from pymongo import MongoClient
from bson import ObjectId
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# MongoDB connection
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
DB_NAME = os.getenv('DB_NAME', 'file_tracker')

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
files_collection = db.files

# Create indexes for better performance
files_collection.create_index("filename")
files_collection.create_index("disk_id")
files_collection.create_index([("filename", "text")])

class FileTracker:
    @staticmethod
    def add_file(filename, location, disk_id, file_size=None, file_type=None):
        """Add a new file to the tracking system"""
        file_doc = {
            'filename': filename,
            'location': location,
            'disk_id': disk_id,
            'file_size': file_size,
            'file_type': file_type,
            'date_added': datetime.utcnow(),
            'last_verified': None
        }
        result = files_collection.insert_one(file_doc)
        return str(result.inserted_id)
    
    @staticmethod
    def find_files(query=None, disk_id=None):
        """Search for files by name or disk ID"""
        search_filter = {}
        
        if query:
            search_filter['$text'] = {'$search': query}
        
        if disk_id:
            search_filter['disk_id'] = disk_id
            
        files = list(files_collection.find(search_filter))
        
        # Convert ObjectId to string for JSON serialization
        for file in files:
            file['_id'] = str(file['_id'])
            
        return files
    
    @staticmethod
    def get_all_files():
        """Get all files in the system"""
        files = list(files_collection.find())
        for file in files:
            file['_id'] = str(file['_id'])
        return files
    
    @staticmethod
    def get_disk_summary():
        """Get summary of files per disk"""
        pipeline = [
            {
                '$group': {
                    '_id': '$disk_id',
                    'file_count': {'$sum': 1},
                    'total_size': {'$sum': '$file_size'}
                }
            },
            {
                '$sort': {'_id': 1}
            }
        ]
        return list(files_collection.aggregate(pipeline))
    
    @staticmethod
    def update_file(file_id, updates):
        """Update file information"""
        updates['last_modified'] = datetime.utcnow()
        result = files_collection.update_one(
            {'_id': ObjectId(file_id)}, 
            {'$set': updates}
        )
        return result.modified_count > 0
    
    @staticmethod
    def delete_file(file_id):
        """Delete a file from tracking"""
        result = files_collection.delete_one({'_id': ObjectId(file_id)})
        return result.deleted_count > 0
    
    @staticmethod
    def verify_file_exists(file_id):
        """Mark a file as verified (exists on disk)"""
        result = files_collection.update_one(
            {'_id': ObjectId(file_id)},
            {'$set': {'last_verified': datetime.utcnow()}}
        )
        return result.modified_count > 0

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/files', methods=['GET'])
def get_files():
    """Get all files or search files"""
    query = request.args.get('q')
    disk_id = request.args.get('disk_id')
    
    if query or disk_id:
        files = FileTracker.find_files(query=query, disk_id=disk_id)
    else:
        files = FileTracker.get_all_files()
    
    return jsonify(files)

@app.route('/api/files', methods=['POST'])
def add_file():
    """Add a new file to tracking"""
    data = request.get_json()
    
    required_fields = ['filename', 'location', 'disk_id']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields: filename, location, disk_id'}), 400
    
    file_id = FileTracker.add_file(
        filename=data['filename'],
        location=data['location'],
        disk_id=data['disk_id'],
        file_size=data.get('file_size'),
        file_type=data.get('file_type')
    )
    
    return jsonify({'id': file_id, 'message': 'File added successfully'}), 201

@app.route('/api/files/<file_id>', methods=['PUT'])
def update_file(file_id):
    """Update file information"""
    data = request.get_json()
    
    if FileTracker.update_file(file_id, data):
        return jsonify({'message': 'File updated successfully'})
    else:
        return jsonify({'error': 'File not found'}), 404

@app.route('/api/files/<file_id>', methods=['DELETE'])
def delete_file(file_id):
    """Delete a file from tracking"""
    if FileTracker.delete_file(file_id):
        return jsonify({'message': 'File deleted successfully'})
    else:
        return jsonify({'error': 'File not found'}), 404

@app.route('/api/files/<file_id>/verify', methods=['POST'])
def verify_file(file_id):
    """Mark file as verified"""
    if FileTracker.verify_file_exists(file_id):
        return jsonify({'message': 'File verified successfully'})
    else:
        return jsonify({'error': 'File not found'}), 404

@app.route('/api/summary')
def get_summary():
    """Get disk summary"""
    summary = FileTracker.get_disk_summary()
    return jsonify(summary)

@app.route('/api/disks')
def get_disks():
    """Get list of all disk IDs"""
    disks = files_collection.distinct('disk_id')
    return jsonify(disks)

if __name__ == '__main__':
    app.run(debug=True)

# models.py (Optional: More structured approach)
from datetime import datetime
from typing import Optional, Dict, Any

class FileModel:
    def __init__(self, filename: str, location: str, disk_id: str, 
                 file_size: Optional[int] = None, file_type: Optional[str] = None):
        self.filename = filename
        self.location = location
        self.disk_id = disk_id
        self.file_size = file_size
        self.file_type = file_type
        self.date_added = datetime.utcnow()
        self.last_verified = None
        self.last_modified = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'filename': self.filename,
            'location': self.location,
            'disk_id': self.disk_id,
            'file_size': self.file_size,
            'file_type': self.file_type,
            'date_added': self.date_added,
            'last_verified': self.last_verified,
            'last_modified': self.last_modified
        }
"""
# config.py
"""
import os

class Config:
    MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
    DB_NAME = os.getenv('DB_NAME', 'file_tracker')
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here')
"""

# .env (create this file)
"""
MONGO_URI=mongodb://localhost:27017/
DB_NAME=file_tracker
SECRET_KEY=your-secret-key-change-this
"""

# templates/index.html
"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Tracker</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .search-bar { margin-bottom: 20px; }
        .search-bar input, .search-bar select, .search-bar button { 
            padding: 8px; margin-right: 10px; 
        }
        .file-list { border-collapse: collapse; width: 100%; }
        .file-list th, .file-list td { 
            border: 1px solid #ddd; padding: 8px; text-align: left; 
        }
        .file-list th { background-color: #f2f2f2; }
        .add-file-form { background: #f9f9f9; padding: 20px; margin-bottom: 20px; }
        .add-file-form input, .add-file-form button { 
            padding: 8px; margin: 5px; 
        }
        .summary { background: #e9f4ff; padding: 15px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>File Tracker Dashboard</h1>
        
        <div class="summary" id="summary">
            Loading summary...
        </div>
        
        <div class="add-file-form">
            <h3>Add New File</h3>
            <input type="text" id="filename" placeholder="Filename" required>
            <input type="text" id="location" placeholder="Full path/location" required>
            <input type="text" id="disk_id" placeholder="Disk ID" required>
            <input type="number" id="file_size" placeholder="File size (bytes)">
            <input type="text" id="file_type" placeholder="File type">
            <button onclick="addFile()">Add File</button>
        </div>
        
        <div class="search-bar">
            <input type="text" id="searchQuery" placeholder="Search files...">
            <select id="diskFilter">
                <option value="">All Disks</option>
            </select>
            <button onclick="searchFiles()">Search</button>
            <button onclick="loadAllFiles()">Show All</button>
        </div>
        
        <table class="file-list">
            <thead>
                <tr>
                    <th>Filename</th>
                    <th>Location</th>
                    <th>Disk ID</th>
                    <th>File Size</th>
                    <th>Type</th>
                    <th>Date Added</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody id="fileTableBody">
                <tr><td colspan="7">Loading files...</td></tr>
            </tbody>
        </table>
    </div>

    <script>
        // Load initial data
        document.addEventListener('DOMContentLoaded', function() {
            loadSummary();
            loadDisks();
            loadAllFiles();
        });

        async function loadSummary() {
            try {
                const response = await fetch('/api/summary');
                const summary = await response.json();
                
                let summaryHtml = '<h3>Disk Summary</h3>';
                summary.forEach(disk => {
                    const sizeGB = disk.total_size ? (disk.total_size / (1024*1024*1024)).toFixed(2) : 'N/A';
                    summaryHtml += `<p><strong>${disk._id}:</strong> ${disk.file_count} files, ${sizeGB} GB</p>`;
                });
                
                document.getElementById('summary').innerHTML = summaryHtml;
            } catch (error) {
                console.error('Error loading summary:', error);
            }
        }

        async function loadDisks() {
            try {
                const response = await fetch('/api/disks');
                const disks = await response.json();
                
                const select = document.getElementById('diskFilter');
                disks.forEach(disk => {
                    const option = document.createElement('option');
                    option.value = disk;
                    option.textContent = disk;
                    select.appendChild(option);
                });
            } catch (error) {
                console.error('Error loading disks:', error);
            }
        }

        async function loadAllFiles() {
            try {
                const response = await fetch('/api/files');
                const files = await response.json();
                displayFiles(files);
            } catch (error) {
                console.error('Error loading files:', error);
            }
        }

        async function searchFiles() {
            const query = document.getElementById('searchQuery').value;
            const diskId = document.getElementById('diskFilter').value;
            
            let url = '/api/files?';
            if (query) url += `q=${encodeURIComponent(query)}&`;
            if (diskId) url += `disk_id=${encodeURIComponent(diskId)}&`;
            
            try {
                const response = await fetch(url);
                const files = await response.json();
                displayFiles(files);
            } catch (error) {
                console.error('Error searching files:', error);
            }
        }

        function displayFiles(files) {
            const tbody = document.getElementById('fileTableBody');
            
            if (files.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7">No files found</td></tr>';
                return;
            }
            
            tbody.innerHTML = files.map(file => `
                <tr>
                    <td>${file.filename}</td>
                    <td>${file.location}</td>
                    <td>${file.disk_id}</td>
                    <td>${file.file_size ? formatFileSize(file.file_size) : 'N/A'}</td>
                    <td>${file.file_type || 'N/A'}</td>
                    <td>${new Date(file.date_added).toLocaleDateString()}</td>
                    <td>
                        <button onclick="verifyFile('${file._id}')">Verify</button>
                        <button onclick="deleteFile('${file._id}')">Delete</button>
                    </td>
                </tr>
            `).join('');
        }

        async function addFile() {
            const fileData = {
                filename: document.getElementById('filename').value,
                location: document.getElementById('location').value,
                disk_id: document.getElementById('disk_id').value,
                file_size: parseInt(document.getElementById('file_size').value) || null,
                file_type: document.getElementById('file_type').value || null
            };

            if (!fileData.filename || !fileData.location || !fileData.disk_id) {
                alert('Please fill in required fields: filename, location, and disk ID');
                return;
            }

            try {
                const response = await fetch('/api/files', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(fileData)
                });

                if (response.ok) {
                    alert('File added successfully!');
                    document.querySelectorAll('.add-file-form input').forEach(input => input.value = '');
                    loadAllFiles();
                    loadSummary();
                } else {
                    alert('Error adding file');
                }
            } catch (error) {
                console.error('Error adding file:', error);
                alert('Error adding file');
            }
        }

        async function verifyFile(fileId) {
            try {
                const response = await fetch(`/api/files/${fileId}/verify`, { method: 'POST' });
                if (response.ok) {
                    alert('File verified successfully!');
                } else {
                    alert('Error verifying file');
                }
            } catch (error) {
                console.error('Error verifying file:', error);
            }
        }

        async function deleteFile(fileId) {
            if (!confirm('Are you sure you want to delete this file record?')) return;

            try {
                const response = await fetch(`/api/files/${fileId}`, { method: 'DELETE' });
                if (response.ok) {
                    alert('File deleted successfully!');
                    loadAllFiles();
                    loadSummary();
                } else {
                    alert('Error deleting file');
                }
            } catch (error) {
                console.error('Error deleting file:', error);
            }
        }

        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
    </script>
</body>
</html>
"""

# bulk_scanner.py - Utility script to scan directories and add files
"""
import os
import requests
import json
from pathlib import Path

class BulkFileScanner:
    def __init__(self, api_base_url='http://localhost:5000'):
        self.api_base_url = api_base_url
    
    def scan_directory(self, directory_path, disk_id, extensions=None):
        '''
        Scan a directory and add all files to the tracking system
        
        Args:
            directory_path: Path to scan
            disk_id: ID of the disk/drive
            extensions: List of file extensions to include (e.g., ['.jpg', '.mp4'])
        '''
        directory = Path(directory_path)
        if not directory.exists():
            print(f"Directory {directory_path} does not exist")
            return
        
        files_added = 0
        errors = 0
        
        for file_path in directory.rglob('*'):
            if file_path.is_file():
                # Filter by extensions if provided
                if extensions and file_path.suffix.lower() not in extensions:
                    continue
                
                try:
                    file_data = {
                        'filename': file_path.name,
                        'location': str(file_path.relative_to(directory)),
                        'disk_id': disk_id,
                        'file_size': file_path.stat().st_size,
                        'file_type': file_path.suffix.lower()
                    }
                    
                    response = requests.post(
                        f'{self.api_base_url}/api/files',
                        json=file_data,
                        headers={'Content-Type': 'application/json'}
                    )
                    
                    if response.status_code == 201:
                        files_added += 1
                        if files_added % 100 == 0:
                            print(f"Added {files_added} files...")
                    else:
                        print(f"Error adding {file_path.name}: {response.text}")
                        errors += 1
                        
                except Exception as e:
                    print(f"Error processing {file_path}: {e}")
                    errors += 1
        
        print(f"Scan complete: {files_added} files added, {errors} errors")
    
    def scan_multiple_directories(self, scan_config):
        '''
        Scan multiple directories based on configuration
        
        scan_config example:
        [
            {'path': '/media/disk1', 'disk_id': 'DISK_001', 'extensions': ['.jpg', '.png']},
            {'path': '/media/disk2', 'disk_id': 'DISK_002'}
        ]
        '''
        for config in scan_config:
            print(f"Scanning {config['path']} for disk {config['disk_id']}...")
            self.scan_directory(
                config['path'], 
                config['disk_id'], 
                config.get('extensions')
            )

# Example usage of bulk scanner
if __name__ == '__main__':
    scanner = BulkFileScanner()
    
    # Example: Scan a single directory
    # scanner.scan_directory('/path/to/your/external/drive', 'EXTERNAL_001')
    
    # Example: Scan multiple directories with different configurations
    scan_config = [
        {
            'path': '/media/photos_drive', 
            'disk_id': 'PHOTOS_001', 
            'extensions': ['.jpg', '.jpeg', '.png', '.tiff', '.raw']
        },
        {
            'path': '/media/videos_drive', 
            'disk_id': 'VIDEOS_001', 
            'extensions': ['.mp4', '.avi', '.mkv', '.mov']
        }
    ]
    # scanner.scan_multiple_directories(scan_config)
"""
