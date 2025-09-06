# FaithFind Backend

This is the backend API server for the FaithFind project. It is built with Flask and designed to be deployed on Render.

## Features
- RESTful API built with Flask
- CORS support
- PostgreSQL database integration
- Environment variable support via python-dotenv

## Setup
1. Clone this repository:
   ```sh
   git clone <your-repo-url>
   cd faithfind-backend
   ```
2. Create a `.env` file for your environment variables (do not commit this file).
3. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```
4. Run the server locally:
   ```sh
   flask run
   ```

## Deployment (Render)
- Ensure `Procfile`, `requirements.txt`, and `runtime.txt` are present.
- Set environment variables in Render dashboard (e.g., `DATABASE_URL`, `SECRET_KEY`).
- Render will use the `Procfile` to start the server.

## Project Structure
- `api_server.py`: Main Flask application
- `requirements.txt`: Python dependencies
- `Procfile`: Entrypoint for deployment
- `runtime.txt`: Python version

## License
MIT
