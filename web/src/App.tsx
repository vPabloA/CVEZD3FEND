import { Route, Routes } from "react-router-dom";
import Layout from "@/components/Layout";
import HomePage from "@/pages/HomePage";
import RoutePage from "@/pages/RoutePage";
import NodeDetailPage from "@/pages/NodeDetailPage";
import CoveragePage from "@/pages/CoveragePage";
import SocActionPackPage from "@/pages/SocActionPackPage";
import AiReviewPage from "@/pages/AiReviewPage";
import EmptyState from "@/components/EmptyState";

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<HomePage />} />
        <Route path="route/:routeId" element={<RoutePage />} />
        <Route path="node/:nodeId" element={<NodeDetailPage />} />
        <Route path="coverage" element={<CoveragePage />} />
        <Route path="soc-action-pack/:id" element={<SocActionPackPage />} />
        <Route path="ai-review" element={<AiReviewPage />} />
        <Route
          path="*"
          element={
            <EmptyState title="Page not found" hint="Use the navigation above to get back on track." />
          }
        />
      </Route>
    </Routes>
  );
}
