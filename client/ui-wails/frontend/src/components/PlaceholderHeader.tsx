export default function PlaceholderHeader() {
  return (
    <div
      className="h-[36px] shrink-0 cursor-default"
      style={{ "--wails-draggable": "drag" } as React.CSSProperties}
    />
  );
}
