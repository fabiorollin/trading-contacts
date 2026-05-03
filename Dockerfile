FROM node:20-alpine
WORKDIR /app

# Install deps first for layer caching
COPY package.json ./
RUN npm install --omit=dev

# Then app source
COPY server.js ./
COPY public ./public

EXPOSE 8080
USER node
CMD ["node", "server.js"]
