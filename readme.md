# Secure Webcam Capture App

A simple web application that allows users to capture photos from their webcam and securely send them to a Flask backend for encrypted storage.

## Features

- Clean, user-friendly interface
- Multi-camera support with camera selection dropdown
- Webcam capture functionality
- Flask API endpoint for image storage
- Encrypted image storage using Fernet symmetric encryption
- Cross-Origin Resource Sharing (CORS) support

## Project Structure

```
secure-webcam-app/
├── index.html            # Frontend UI
├── app.py                # Flask backend server
├── requirements.txt      # Python dependencies
└── README.md
```

## Setup and Installation

1. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the Flask server:
   ```bash
   python app.py
   ```
   - The app will automatically create index.html if it doesn't exist in the same directory as app.py

4. Open your browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```

The Flask server will serve both the frontend interface and handle the API requests.

## Security Notes

- The encryption key is derived from a password stored in the code. In a production environment, use environment variables or a secure key management system.
- Images are stored encrypted on disk in the `secure_images` directory.
- The application uses PBKDF2 for key derivation with 100,000 iterations for security.

## How It Works

1. The frontend captures an image from the webcam when the user clicks "Take Photo".
2. The image is converted to base64 format.
3. When the user clicks "Save Securely", the image is sent to the Flask backend API.
4. The backend decodes the base64 image, encrypts it using Fernet symmetric encryption, and saves it to disk.
5. Metadata about the image (timestamps, etc.) is stored separately.

## Customization

- Change the `PASSWORD` variable in `app.py` to a secure password of your choice.
- Modify the UI styling in `index.html` as needed.
- Add additional features like image listing, viewing, or deleting as required.

## License

This project is open-source and free to use for educational purposes.