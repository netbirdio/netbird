import type { LucideIcon } from "lucide-react";
import { ConnectionLine } from "./ConnectionLine";

interface StatusCardProps {
  icon: LucideIcon;
  label: string;
  detail?: string;
  success?: boolean;
  line?: boolean;
}

export function StatusCard({
  icon: Icon,
  label,
  detail,
  success = true,
  line = true,
}: Readonly<StatusCardProps>) {
  return (
    <>
      {line && <ConnectionLine success={success} />}
      <div className="flex flex-col items-center gap-2">
        <div className="w-14 h-14 rounded-md flex items-center justify-center from-nb-gray-940 to-nb-gray-930/70 bg-gradient-to-br border border-nb-gray-910">
          <Icon size={20} className="text-nb-gray-200" />
        </div>
        <span className="text-sm text-nb-gray-200 font-normal mt-1">{label}</span>
        <span className={`text-xs font-medium uppercase ${success ? "text-green-500" : "text-netbird"}`}>
          {success ? "Connected" : "Unreachable"}
        </span>
        {detail && (
          <span className="text-xs text-nb-gray-400 truncate text-center">
            {detail}
          </span>
        )}
      </div>
    </>
  );
}
