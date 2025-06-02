# Deploying to Railway

## Prerequisites

1. A [Railway](https://railway.app/) account
2. [Railway CLI](https://docs.railway.app/develop/cli) installed (optional, for local development)
3. Git installed on your machine

## Setup Steps

### 1. Prepare Your Repository

The repository has been configured with the necessary files for Railway deployment:

- `Procfile`: Defines the command to run the application
- `runtime.txt`: Specifies the Python version
- `railway.json`: Contains Railway-specific configuration
- `.env.example`: Template for required environment variables

### 2. Create a New Project on Railway

1. Log in to your [Railway Dashboard](https://railway.app/dashboard)
2. Click "New Project"
3. Select "Deploy from GitHub repo"
4. Connect your GitHub account if not already connected
5. Select this repository

### 3. Configure Environment Variables

In your Railway project dashboard:

1. Go to the "Variables" tab
2. Add the following environment variables (refer to `.env.example` for the complete list):
   - `DATABASE_URL`: Your PostgreSQL connection string
   - `GROQ_API_KEY`: Your GROQ API key
   - Other variables as needed

### 4. Set Up Database

You have two options:

#### Option 1: Use Railway's PostgreSQL Plugin

1. In your project, click "+ New"
2. Select "Database" → "PostgreSQL"
3. Railway will automatically add the database connection variables to your project

#### Option 2: Use External Database (e.g., Neon)

1. Set the `DATABASE_URL` and related environment variables to point to your external database

### 5. Deploy Your Application

Railway will automatically deploy your application when you push changes to your repository.

1. Monitor the deployment in the "Deployments" tab
2. Once deployed, click on the generated domain URL to access your application

### 6. Verify Deployment

1. Visit `https://your-railway-url.railway.app/` to see the welcome message
2. Visit `https://your-railway-url.railway.app/docs` to access the API documentation

## Troubleshooting

### Logs

Check the logs in the Railway dashboard for any errors:

1. Go to the "Deployments" tab
2. Click on the latest deployment
3. View the logs

### Common Issues

1. **Database Connection Errors**: Ensure your `DATABASE_URL` is correctly formatted and the database is accessible
2. **Missing Environment Variables**: Check that all required environment variables are set
3. **Build Failures**: Review the build logs for any package installation errors

## Local Development with Railway

To develop locally using Railway's environment:

1. Install the Railway CLI: `npm i -g @railway/cli`
2. Login: `railway login`
3. Link to your project: `railway link`
4. Run locally: `railway run uvicorn app.main:app --reload`

This will run your application locally with the environment variables from your Railway project.