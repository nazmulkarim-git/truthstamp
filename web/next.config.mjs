/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: "https://truthstamp-api.onrender.com/:path*",
      },
    ];
  },
};

export default nextConfig;