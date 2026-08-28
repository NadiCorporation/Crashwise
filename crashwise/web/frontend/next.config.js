/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  async rewrites() {
    return [
      { source: "/api/:path*", destination: `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/api/:path*` },
      { source: "/campaigns/:path*", destination: `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/campaigns/:path*` },
      { source: "/campaigns", destination: `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/campaigns` },
      { source: "/crashes/:path*", destination: `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/crashes/:path*` },
      { source: "/workers", destination: `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/workers` },
      { source: "/health", destination: `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/health` },
    ];
  },
};
module.exports = nextConfig;
