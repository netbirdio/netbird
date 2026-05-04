import { Outlet } from "react-router-dom";
import PlaceholderHeader from "@/components/PlaceholderHeader";

export default function Layout() {
  return (
    <div className="flex h-full flex-col">
      <PlaceholderHeader />
      <div className="flex min-h-0 flex-1">
        <main className="flex-1 overflow-hidden">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
