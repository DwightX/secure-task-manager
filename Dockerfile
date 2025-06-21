# syntax=docker/dockerfile:1
FROM node:lts-alpine
WORKDIR /app

# Copy package files first
COPY package*.json ./

# Install dependencies in the container (builds native modules correctly)
RUN npm install --production

# Copy application code (but NOT node_modules)
COPY . .

# Make sure we don't copy local node_modules
# Add .dockerignore file with:
# node_modules

# Expose port and start
EXPOSE 3000
CMD ["node", "server.js"]