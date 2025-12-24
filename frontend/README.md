# pwsafe-service Frontend

React frontend for the pwsafe-service project, providing a web interface for accessing Password Safe (.psafe3) files.

## Development Prerequisites

- **Node.js**: Version 24 or later
- **npm**: Comes with Node.js

Verify Node.js installation:

```bash
node --version
npm --version
```

## Getting Started

### 1. Install Dependencies

```bash
cd frontend
npm install
```

### 2. Build the Application

```bash
npm run build
```

### 3. Run the Development Server

```bash
npm run dev
```

The application will be available at `http://localhost:3000` by default.

## Configuration

The frontend expects the backend API to be available at `http://localhost:8080` by default. Make sure the backend service is running before using the frontend.

## Scripts

| Script                 | Description                              |
| ---------------------- | ---------------------------------------- |
| `npm run dev`          | Start development server with watch mode |
| `npm run build`        | Build production bundle                  |
| `npm start`            | Serve production build                   |
| `npm run format`       | Format code with Prettier                |
| `npm run format:check` | Check code formatting                    |

## Development Workflow

1. **Start the backend** service (see backend/README.md)
2. **Start development server**: `npm run dev`
3. **Make changes** to code in `src/`
4. **Format code**: `npm run format`
5. **Build for production**: `npm run build`
6. **Commit** your changes
