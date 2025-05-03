from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
import base64
import os
import time
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import io


app = Flask(__name__, static_folder='static')
CORS(app)  # Enable CORS for all routes

# Create static directory for frontend files if it doesn't exist
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
if not os.path.exists(STATIC_DIR):
    os.makedirs(STATIC_DIR)

# Create storage directory if it doesn't exist
STORAGE_DIR = 'secure_images'
if not os.path.exists(STORAGE_DIR):
    os.makedirs(STORAGE_DIR)

# Key files
PRIVATE_KEY_FILE = os.path.join(STORAGE_DIR, "private_key.pem")
PUBLIC_KEY_FILE = os.path.join(STORAGE_DIR, "public_key.pem")

# Generate or load RSA keys
def get_rsa_keys():
    if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
        # Load existing keys
        with open(PRIVATE_KEY_FILE, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        
        with open(PUBLIC_KEY_FILE, "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
    else:
        # Generate new key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Save private key
        with open(PRIVATE_KEY_FILE, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Save public key
        with open(PUBLIC_KEY_FILE, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    
    return private_key, public_key

# Get or generate RSA keys
private_key, public_key = get_rsa_keys()

def encrypt_data(data):
    """Encrypt data using RSA public key"""
    # Since RSA can only encrypt small amounts of data,
    # we'll chunk the data into appropriate sizes
    chunk_size = 190  # Leave room for padding (for 2048-bit key)
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    encrypted_chunks = []
    
    for chunk in chunks:
        encrypted_chunk = public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_chunks.append(encrypted_chunk)
    
    # Return encrypted chunks with their lengths for easier decryption later
    result = []
    for chunk in encrypted_chunks:
        # Store the length (4 bytes) followed by the encrypted chunk
        length = len(chunk).to_bytes(4, byteorder='big')
        result.append(length + chunk)
    
    return b''.join(result)

def decrypt_data(encrypted_data):
    """Decrypt data using RSA private key"""
    # Parse the encrypted chunks
    data = io.BytesIO(encrypted_data)
    decrypted_chunks = []
    
    while data.tell() < len(encrypted_data):
        # Read the length (4 bytes)
        chunk_length = int.from_bytes(data.read(4), byteorder='big')
        # Read the chunk
        encrypted_chunk = data.read(chunk_length)
        
        # Decrypt the chunk
        decrypted_chunk = private_key.decrypt(
            encrypted_chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_chunks.append(decrypted_chunk)
    
    # Combine decrypted chunks
    return b''.join(decrypted_chunks)

def save_temp_image(image_bytes):
    """Save image to a temporary file and return its filename"""
    temp_filename = f"temp_{int(time.time())}.jpg"
    temp_path = os.path.join(STORAGE_DIR, temp_filename)
    with open(temp_path, 'wb') as f:
        f.write(image_bytes)
    return temp_filename

@app.route('/api/upload', methods=['POST'])
def upload_image():
    try:
        # Get data from request
        data = request.json
        if not data or 'image' not in data:
            return jsonify({"error": "No image data provided"}), 400
        
        # Decode base64 image
        image_data = base64.b64decode(data['image'])
        
        # Encrypt image data
        encrypted_data = encrypt_data(image_data)
        
        # Generate unique filename based on timestamp
        timestamp = int(time.time())
        filename = f"image_{timestamp}.enc"
        filepath = os.path.join(STORAGE_DIR, filename)
        
        # Save encrypted image
        with open(filepath, 'wb') as f:
            f.write(encrypted_data)
        
        # Save metadata (timestamp, etc.)
        metadata = {
            "original_timestamp": data.get('timestamp', ''),
            "server_timestamp": timestamp,
            "filename": filename
        }
        
        metadata_path = os.path.join(STORAGE_DIR, f"metadata_{timestamp}.json")
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f)
        
        return jsonify({"success": True, "filename": filename}), 200
    
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Utility endpoint to check if server is running
@app.route('/api/status', methods=['GET'])
def status():
    return jsonify({"status": "running"})

# Optional: Endpoint to list saved images
@app.route('/api/images', methods=['GET'])
def list_images():
    files = []
    for filename in os.listdir(STORAGE_DIR):
        if filename.endswith('.enc'):
            files.append(filename)
    return jsonify({"images": files})

# Decrypt and return an image
@app.route('/api/decrypt/<filename>', methods=['GET'])
def decrypt_image(filename):
    try:
        # Validate filename
        if not filename.endswith('.enc'):
            return jsonify({"error": "Invalid file type"}), 400
        
        # Construct full path
        filepath = os.path.join(STORAGE_DIR, filename)
        if not os.path.exists(filepath):
            return jsonify({"error": "File not found"}), 404
        
        # Read encrypted data
        with open(filepath, 'rb') as f:
            encrypted_data = f.read()
        
        # Decrypt the data
        decrypted_data = decrypt_data(encrypted_data)
        
        # Return the image data as response
        return send_from_directory(
            directory=STORAGE_DIR,
            path=save_temp_image(decrypted_data),
            mimetype='image/jpeg'
        )
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Endpoint to download the public key
@app.route('/api/public-key', methods=['GET'])
def get_public_key():
    try:
        with open(PUBLIC_KEY_FILE, 'rb') as f:
            key_data = f.read()
        return key_data, 200, {'Content-Type': 'application/x-pem-file'}
    except Exception as e:
        print(f"Error retrieving public key: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Serve the frontend
@app.route('/')
def index():
    # Get the root directory of the application
    root_dir = os.path.dirname(os.path.abspath(__file__))
    # First try the current directory
    if os.path.exists(os.path.join(root_dir, 'index.html')):
        return send_from_directory(root_dir, 'index.html')
    # Then try the parent directory
    elif os.path.exists(os.path.join(os.path.dirname(root_dir), 'index.html')):
        return send_from_directory(os.path.dirname(root_dir), 'index.html')
    else:
        # If we can't find the file, return a helpful error message
        return "index.html not found. Please place the index.html file in the same directory as app.py or in the parent directory."

# Serve the frontend from /index.html path too
@app.route('/index.html')
def index_html():
    return index()  # Reuse the index route function

if __name__ == '__main__':
    # Check if index.html exists, if not create it
    root_dir = os.path.dirname(os.path.abspath(__file__))
    index_path = os.path.join(root_dir, 'index.html')
    
    if not os.path.exists(index_path):
        print(f"Creating index.html in {root_dir}")
        with open(index_path, 'w') as f:
            f.write('''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Webcam Capture App</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f7fa;
            color: #333;
        }
        h1 {
            color: #2c3e50;
            text-align: center;
            margin-bottom: 30px;
        }
        .container {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 20px;
        }
        .camera-select {
            width: 100%;
            max-width: 640px;
            margin-bottom: 10px;
        }
        select {
            width: 100%;
            padding: 10px;
            border-radius: 6px;
            border: 1px solid #ddd;
            background-color: white;
            font-size: 16px;
        }
        .video-container {
            position: relative;
            width: 100%;
            max-width: 640px;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }
        #video {
            width: 100%;
            height: auto;
            background-color: #000;
            display: block;
        }
        #canvas {
            display: none;
        }
        .preview {
            width: 100%;
            max-width: 640px;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            display: none;
        }
        #capturedImage {
            width: 100%;
            height: auto;
        }
        .controls {
            display: flex;
            gap: 15px;
            margin-top: 10px;
        }
        button {
            padding: 12px 20px;
            font-size: 16px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.3s ease;
            font-weight: 500;
        }
        #captureBtn {
            background-color: #3498db;
            color: white;
        }
        #captureBtn:hover {
            background-color: #2980b9;
        }
        #sendBtn {
            background-color: #2ecc71;
            color: white;
            display: none;
        }
        #sendBtn:hover {
            background-color: #27ae60;
        }
        #retakeBtn {
            background-color: #e74c3c;
            color: white;
            display: none;
        }
        #retakeBtn:hover {
            background-color: #c0392b;
        }
        .status {
            margin-top: 20px;
            padding: 10px;
            border-radius: 4px;
            text-align: center;
            font-weight: 500;
        }
        .success {
            background-color: #d5f5e3;
            color: #27ae60;
            display: none;
        }
        .error {
            background-color: #fadbd8;
            color: #e74c3c;
            display: none;
        }
        .security-info {
            margin-top: 30px;
            padding: 15px;
            background-color: #eaf2f8;
            border-radius: 8px;
            border-left: 4px solid #3498db;
        }
        .security-info h3 {
            margin-top: 0;
            color: #2980b9;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Secure Webcam Capture</h1>
        
        <div class="camera-select">
            <select id="cameraSelect">
                <option value="">Loading cameras...</option>
            </select>
        </div>
        
        <div class="video-container">
            <video id="video" autoplay playsinline></video>
            <canvas id="canvas"></canvas>
        </div>
        
        <div class="preview">
            <img id="capturedImage" alt="Captured image">
        </div>
        
        <div class="controls">
            <button id="captureBtn">Take Photo</button>
            <button id="retakeBtn">Retake</button>
            <button id="sendBtn">Save Securely</button>
        </div>
        
        <div class="status success" id="successMessage">
            Image securely saved to server!
        </div>
        
        <div class="status error" id="errorMessage">
            Error: Could not save image.
        </div>
        
        <div class="security-info">
            <h3>Security Information</h3>
            <p>This application uses RSA asymmetric encryption to secure your images. Images are encrypted with a public key before transmission, and can only be decrypted with the private key stored securely on the server.</p>
            <p><a href="/api/public-key" download="public_key.pem">Download Public Key</a></p>
        </div>
    </div>

    <script>
        // DOM elements
        const video = document.getElementById('video');
        const canvas = document.getElementById('canvas');
        const capturedImage = document.getElementById('capturedImage');
        const captureBtn = document.getElementById('captureBtn');
        const retakeBtn = document.getElementById('retakeBtn');
        const sendBtn = document.getElementById('sendBtn');
        const successMessage = document.getElementById('successMessage');
        const errorMessage = document.getElementById('errorMessage');
        const videoContainer = document.querySelector('.video-container');
        const preview = document.querySelector('.preview');
        const cameraSelect = document.getElementById('cameraSelect');
        
        // Global variables
        let currentStream = null;
        
        // Get list of available cameras
        async function getCameras() {
            try {
                const devices = await navigator.mediaDevices.enumerateDevices();
                const videoDevices = devices.filter(device => device.kind === 'videoinput');
                
                // Clear the dropdown
                cameraSelect.innerHTML = '';
                
                if (videoDevices.length === 0) {
                    const option = document.createElement('option');
                    option.text = 'No cameras found';
                    cameraSelect.add(option);
                    errorMessage.textContent = "No cameras detected on your device.";
                    errorMessage.style.display = "block";
                    return;
                }
                
                // Add cameras to dropdown
                videoDevices.forEach((device, index) => {
                    const option = document.createElement('option');
                    option.value = device.deviceId;
                    option.text = device.label || `Camera ${index + 1}`;
                    cameraSelect.add(option);
                });
                
                // Select first camera by default
                startCamera(videoDevices[0].deviceId);
            } catch (err) {
                console.error("Error enumerating devices:", err);
                errorMessage.textContent = "Error detecting cameras. Please ensure permissions are granted.";
                errorMessage.style.display = "block";
            }
        }
        
        // Get access to webcam
        async function startCamera(deviceId = null) {
            try {
                // Stop any existing stream
                if (currentStream) {
                    currentStream.getTracks().forEach(track => {
                        track.stop();
                    });
                }
                
                // Set constraints based on selected device
                const constraints = {
                    video: deviceId ? { deviceId: { exact: deviceId } } : true,
                    audio: false
                };
                
                const stream = await navigator.mediaDevices.getUserMedia(constraints);
                video.srcObject = stream;
                currentStream = stream;
                
                // Hide error message if it was displayed
                errorMessage.style.display = "none";
            } catch (err) {
                console.error("Error accessing webcam:", err);
                errorMessage.textContent = "Error: Cannot access webcam. Please ensure you've granted camera permissions.";
                errorMessage.style.display = "block";
            }
        }
        
        // Listen for camera selection changes
        cameraSelect.addEventListener('change', function() {
            if (this.value) {
                startCamera(this.value);
            }
        });

        // Capture image from webcam
        captureBtn.addEventListener('click', function() {
            // Set canvas dimensions to match video
            canvas.width = video.videoWidth;
            canvas.height = video.videoHeight;
            
            // Draw current video frame to canvas
            const context = canvas.getContext('2d');
            context.drawImage(video, 0, 0, canvas.width, canvas.height);
            
            // Convert canvas to image
            const imageDataUrl = canvas.toDataURL('image/jpeg');
            capturedImage.src = imageDataUrl;
            
            // Show preview and controls
            videoContainer.style.display = 'none';
            preview.style.display = 'block';
            captureBtn.style.display = 'none';
            retakeBtn.style.display = 'inline-block';
            sendBtn.style.display = 'inline-block';
            
            // Reset status messages
            successMessage.style.display = 'none';
            errorMessage.style.display = 'none';
        });

        // Retake photo
        retakeBtn.addEventListener('click', function() {
            // Hide preview, show video
            videoContainer.style.display = 'block';
            preview.style.display = 'none';
            
            // Show/hide buttons
            captureBtn.style.display = 'inline-block';
            retakeBtn.style.display = 'none';
            sendBtn.style.display = 'none';
            
            // Reset status messages
            successMessage.style.display = 'none';
            errorMessage.style.display = 'none';
        });

        // Send image to server
        sendBtn.addEventListener('click', async function() {
            try {
                // Get base64 image data without "data:image/jpeg;base64," prefix
                const imageData = capturedImage.src.split(',')[1];
                
                // Send to server
                const response = await fetch('/api/upload', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ 
                        image: imageData,
                        timestamp: new Date().toISOString()
                    })
                });
                
                if (response.ok) {
                    successMessage.style.display = 'block';
                    errorMessage.style.display = 'none';
                } else {
                    throw new Error('Server error: ' + response.status);
                }
            } catch (err) {
                console.error("Error sending image:", err);
                errorMessage.textContent = "Error: Failed to save image. Please try again.";
                errorMessage.style.display = 'block';
                successMessage.style.display = 'none';
            }
        });

        // Initialize
        async function init() {
            try {
                // First request camera permissions
                await navigator.mediaDevices.getUserMedia({ video: true });
                // Then get camera list
                await getCameras();
            } catch (err) {
                console.error("Initialization error:", err);
                errorMessage.textContent = "Error initializing camera. Please grant camera permissions and refresh.";
                errorMessage.style.display = "block";
            }
        }
        
        // Start the application
        init();
    </script>
</body>
</html>''')
        print(f"Index.html created successfully!")
    
    app.run(debug=True)