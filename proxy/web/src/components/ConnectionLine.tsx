import { X } from "lucide-react";

interface ConnectionLineProps {
  success?: boolean;
}

export function ConnectionLine({ success = true }: Readonly<ConnectionLineProps>) {
  if (success) {
    return (
      <div className="flex-1 flex items-center justify-center h-12 w-full px-5">
        <div className="w-full border-t-2 border-dashed border-green-500" />
      </div>
    );
  }

  return (
    <div className="flex-1 flex items-center justify-center h-12 min-w-10 px-5 relative">
      <div className="w-full border-t-2 border-dashed border-nb-gray-900" />
      <div className="absolute inset-0 flex items-center justify-center">
        <div className="w-8 h-8 rounded-full flex items-center justify-center">
          <X size={18} className="text-netbird" />
        </div>
      </div>
    </div>
  );
}
