import Skeleton from "react-loading-skeleton";

export const SettingsSkeleton = () => {
    return (
        <div className={"flex flex-col gap-6"}>
            <div>
                <Skeleton width={100} height={16} className={"mb-4"} />
                <div>
                    <Skeleton width={100} height={14} />
                    <Skeleton width={400} height={10} />
                </div>
                <div className={"mt-3"}>
                    <Skeleton width={100} height={14} />
                    <Skeleton width={400} height={10} />
                </div>
            </div>
            <div>
                <Skeleton width={100} height={16} className={"mb-4"} />
                <div>
                    <Skeleton width={100} height={14} />
                    <Skeleton width={400} height={10} />
                    <Skeleton width={300} height={10} />
                </div>
            </div>
        </div>
    );
};
