import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Standalone output for the Docker image (infra/docker/Dockerfile.web) --
  // bundles only the production dependency subgraph `next start` needs,
  // instead of shipping the full node_modules tree into the runtime stage.
  output: "standalone",
};

export default nextConfig;
