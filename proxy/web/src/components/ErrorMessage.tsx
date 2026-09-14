export const ErrorMessage = ({ error }: { error?: string }) => {
  return (
    <div className="text-red-400 bg-red-800/20 border border-red-800/50 rounded-lg px-4 py-3 whitespace-break-spaces text-sm">
      {error}
    </div>
  );
};
