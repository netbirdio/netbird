import { ReactNode } from "react";

type Props = {
    children: ReactNode;
};

export const MainRightSide = ({ children }: Props) => {
    return (
        <div
            className={"wails-no-draggable flex-1 min-h-0 min-w-0 flex flex-col bg-nb-gray-935 rounded-xl rounded-br-2xl border border-nb-gray-910"}
        >
            {children}
        </div>
    );
};
