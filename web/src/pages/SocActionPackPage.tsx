import { useMemo } from "react";
import { Link, useParams } from "react-router-dom";
import EmptyState from "@/components/EmptyState";
import ErrorState from "@/components/ErrorState";
import LoadingState from "@/components/LoadingState";
import SocActionPackView from "@/components/SocActionPackView";
import { useBundle } from "@/hooks/useBundle";
import { resolveAttackId } from "@/lib/bundle";
import { buildSocActionPack } from "@/lib/socActionPack";

export default function SocActionPackPage() {
  const { id = "" } = useParams();
  const { bundle, loading, error, reload } = useBundle();

  const attackId = bundle ? resolveAttackId(bundle, id) : undefined;
  const pack = useMemo(() => {
    if (!bundle || !attackId) return undefined;
    try {
      return buildSocActionPack(bundle, attackId);
    } catch {
      return undefined;
    }
  }, [bundle, attackId]);

  if (loading) return <LoadingState label="Loading knowledge bundle…" />;
  if (error) return <ErrorState message={error} onRetry={reload} />;
  if (!bundle) return <ErrorState message="Bundle failed to load." onRetry={reload} />;
  if (!pack) {
    return (
      <EmptyState title={`No SOC Action Pack for "${id}"`} hint="Provide an ATT&CK technique id (e.g. T1059), or a CVE/route id that resolves to one.">
        <Link to="/" className="mt-2 text-sm text-link hover:underline">
          ← Back to search
        </Link>
      </EmptyState>
    );
  }

  return <SocActionPackView bundle={bundle} pack={pack} />;
}
