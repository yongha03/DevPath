# DevPath Frontend

React, TypeScript, Tailwind CSS, and Nginx frontend for DevPath.

## Stack

- React 19
- TypeScript 5
- Vite 8
- Tailwind CSS 4
- Nginx

## Local Run

```bash
cd frontend
npm install
npm run dev
```

The frontend dev entrypoint is `http://localhost:8084`.

API and OAuth-related routes are proxied to the backend at `http://localhost:8082`.

## Docker Dev Hot Reload

Use the dedicated development container when you want immediate frontend reflection without rebuilding the Nginx image every time.

```bash
docker compose up -d
```

- URL: `http://localhost:8084`
- Frontend changes: reflected immediately through the Vite dev server
- Backend API proxy: `http://localhost:8082`

`frontend-dev` is part of the default `docker compose up -d` flow.

Use `frontend` only for production-style static build testing on `http://localhost:8084` with the `frontend-static` profile.

## Build

```bash
cd frontend
npm run build
```

The build output is written to `frontend/dist`.

## Nginx Deploy

```bash
cd frontend
docker build -t devpath-frontend .
docker run --rm -p 8084:80 devpath-frontend
```

Nginx configuration lives in `frontend/nginx/default.conf`.

## Docker Watch

To keep using `http://localhost:8084` while automatically rebuilding the static frontend image, run this from the project root:

```bash
docker compose up --build --watch frontend
```

## First Files To Edit

- `src/App.tsx`
- `src/index.css`
- `vite.config.ts`
- `nginx/default.conf`
