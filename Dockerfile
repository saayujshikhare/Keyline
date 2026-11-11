FROM node:22-alpine
RUN apk add --no-cache su-exec
WORKDIR /app
COPY package.json server.js docker-entrypoint.sh ./
COPY lib ./lib
COPY public ./public
RUN chmod +x docker-entrypoint.sh && mkdir /data && chown node:node /data
ENV HOST=0.0.0.0 PORT=8787 DATA_DIR=/data
# MSGR_PEPPER must be provided at run time and kept OFF the data volume.
VOLUME /data
EXPOSE 8787
ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["node", "--disable-warning=ExperimentalWarning", "server.js"]
