# Backend System Documentation

## Overview

This backend system is built using Python, Flask, SQLAlchemy, and JWT. It provides a set of APIs that can be consumed by a frontend application using Axios. These APIs include functionalities like fetching user information, admin details, and handling user authentication (login).

## Environment Requirements

- Python 3.8

## Installation

First, clone the repository to your local machine:

```bash
git clone [Your Repository URL]
Then, navigate to the project directory and install the required dependencies:
```
```
bash
Copy code
cd [Your Project Directory]
pip install -r requirements.txt
Running the Project
Local Development
To start the project locally, run the following command:
```
```
bash
Copy code
python sqlconnector.py
```

This will set up the local database and start the Flask server for development.

Production Deployment
For deploying on a server, execute the following command:
```
bash
Copy code
python user-add-backend.py
```
This will start the backend service in a production environment.

API Endpoints
The system provides several API endpoints, such as:

GET /user: Fetches user information.
GET /admin: Retrieves admin details.
POST /admin/login: Handles user login.
