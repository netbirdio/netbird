import { ConnectionStatusSwitch } from "@/layouts/ConnectionStatusSwitch.tsx";

export const Main = () => {
    return (
        <div className={"wails-draggable flex flex-1 min-h-0 p-4 gap-4"}>
            <div className={"flex flex-col w-full shrink-0 items-center"}>
                <ConnectionStatusSwitch />
            </div>
        </div>
    );
};
