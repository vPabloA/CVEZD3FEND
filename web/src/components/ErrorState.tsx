// UIX_CONTRACT §3: bundle-load/fetch errors render a readable panel with the
// underlying message and a retry action — never a silent failure or raw stack trace.
export default function ErrorState({
  message,
  onRetry,
}: {
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div role="alert" className="flex flex-col items-start gap-3 rounded-md border border-gap bg-red-50 px-4 py-4 text-gap">
      <p className="font-medium">Something went wrong</p>
      <p className="text-sm">{message}</p>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="rounded border border-gap px-3 py-1 text-sm font-medium text-gap hover:bg-red-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-gap"
        >
          Retry
        </button>
      )}
    </div>
  );
}
