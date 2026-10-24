# ==========================================
# SOC Sentinel — Image de production
# Node 20, deps prod uniquement, utilisateur non-root
# ==========================================

FROM node:20-slim

WORKDIR /app

ENV NODE_ENV=production

# Dépendances prod uniquement
COPY package*.json ./
RUN npm ci --omit=dev

# Application (pas de build : HTML/JS statiques + CommonJS)
COPY server.js ./
COPY src ./src
COPY public ./public

RUN chown -R node:node /app

USER node

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
