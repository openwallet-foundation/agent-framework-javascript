FROM node:22

# Set working directory
WORKDIR /www

# Copy repository files
COPY . . 

RUN corepack enable

# Run pnpm install and build
RUN pnpm install --frozen-lockfile \
    && pnpm build

entrypoint ["pnpm", "run-mediator"]