import { MlInsightsPanel } from "@/components/panels/MlInsightsPanel";
import { usePoll } from "@/hooks/usePoll";
import { api } from "@/lib/api";

export function MlPage() {
  const { data } = usePoll(api.mlMetrics, 8000);
  return <MlInsightsPanel data={data} />;
}
