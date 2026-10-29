import { NetBirdLogo } from "./NetBirdLogo";

export function PoweredByNetBird() {
  return (
    <a
      href="https://netbird.io?utm_source=netbird-proxy&utm_medium=web&utm_campaign=powered_by"
      target="_blank"
      rel="noopener noreferrer"
      className="flex items-center justify-center mt-8 gap-2 group cursor-pointer"
    >
      <span className="text-sm text-nb-gray-400 font-light text-center group-hover:opacity-80 transition-all">
        Powered by
      </span>
      <NetBirdLogo size="small" mobile={false} />
    </a>
  );
}