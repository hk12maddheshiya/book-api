
# Book Review API

A RESTful API built with Node.js, Express, Prisma, and PostgreSQL that supports user authentication (signup/login), book management (CRUD), reviews, pagination, and search functionality.

## Features

* **User Authentication**: Signup and login with JWT-based authentication
* **Books Management**: Create, read (with pagination), and get details with author and review relations
* **Reviews**: Authenticated users can add, update, and delete one review per book
* **Search**: Search books by title or author with pagination
  

## Tech Stack

* **Node.js** & **Express**: Server and routing
* **Prisma**: ORM for database modeling and queries
* **PostgreSQL**: Relational database
* **JWT**: Token-based authentication
* **Zod**: Schema validation (signup)

## Prerequisites

* Node.js v16+ installed
* npm for package management

## Environment Variables

The `.env` file is already set up in the repository. Ensure it contains the following variables:

```env
DATABASE_URL="postgres://avnadmin:AVNS_x4VofLYKssCHnWp-K0s@pg-2e15041-bloging-clone.j.aivencloud.com:26369/defaultdb?sslmode=require"
JWT_KEY="ITSsecret123"
PORT=3000
```

## Installation

```bash
# Clone the repo


# Install dependencies
npm install

# Generate Prisma client and run migrations
npx prisma migrate dev --name init
npx prisma generate
```

## Running the Server

```bash
npm start or node index.js
```

The server will start on `http://localhost:3000` (or the port defined in `.env`).

## API Endpoints

### Authentication

* **POST** `/signup`

  * Body: `{ "email": string, "password": string, "name": string }`
  * Response: `{ message: "Signup successful" }`

* **POST** `/login`

  * Body: `{ "email": string, "password": string }`
  * Response Header: `Authorization: Bearer <token>`
  * Response Body: `{ token: string, message: "Login Successful" }`

### Books

* **POST** `/books` (Protected)

  * Headers: `Authorization: Bearer <token>`
  * Body: `{ "title": string, "author": string, "genre": string }`
  * Response: `{ message: "Book added", book: {...} }`

* **GET** `/books?page={number}&limit={number}`

  * Query params: `page` (0-index), `limit`
  * Response: `{ page, limit, total, totalPages, links: { prev, next }, data: [ ...books ] }`

* **GET** `/books/{id}`

  * Response: Book details including `addedBy` and `reviews`

### Reviews

* **POST** `/books/{id}/reviews` (Protected)

  * Headers: `Authorization: Bearer <token>`
  * Body: `{ "rating": number, "comment": string }`
  * Response: `{ message: "Review added", review: {...} }`

* **PUT** `/reviews/{id}` (Protected)

  * Headers: `Authorization: Bearer <token>`
  * Body: `{ "rating": number, "comment": string }`
  * Response: `{ message: "Review updated", review: {...} }`

* **DELETE** `/reviews/{id}` (Protected)

  * Headers: `Authorization: Bearer <token>`
  * Response: `{ message: "Review deleted" }`

### Search

* **GET** `/search?q={query}&page={number}&limit={number}`

  * Response: Same format as `/books` with filtered results


