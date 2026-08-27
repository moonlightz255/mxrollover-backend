# MxRollover Backend API

RESTful API for MxRollover - eFootball betting management application.

## Tech Stack
- **Node.js** - Runtime environment
- **Express.js** - Web framework
- **MySQL** - Database (Aiven.io)
- **JWT** - Authentication
- **bcryptjs** - Password hashing
- **Render** - Deployment platform

## Features
- User registration & login (username/password)
- JWT-based authentication
- Rollover betting run management
- Bet status tracking (pending/win/loss)
- 10-day rollover step automation

## API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register new user |
| POST | `/api/auth/login` | Login user |

### Rollover Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/rollovers` | Get all rollover runs |
| POST | `/api/rollovers` | Create new rollover run |
| PUT | `/api/bets/:id` | Update bet status |

### Health & Testing
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/test` | API test endpoint |

## Environment Variables

```env
DB_URI=mysql://user:pass@host:port/db?ssl-mode=REQUIRED
PORT=5000
JWT_SECRET=your-secret-key
NODE_ENV=development
