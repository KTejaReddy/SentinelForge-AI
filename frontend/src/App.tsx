import { Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import HomePage from "./pages/HomePage";
import ProjectsPage from "./pages/ProjectsPage";
import ScanPage from "./pages/ScanPage";
import FindingsPage from "./pages/FindingsPage";
import FindingDetailPage from "./pages/FindingDetailPage";
import GraphPage from "./pages/GraphPage";
import ReportPage from "./pages/ReportPage";
import SettingsPage from "./pages/SettingsPage";
import ToolsPage from "./pages/ToolsPage";

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<HomePage />} />
        <Route path="/projects" element={<ProjectsPage />} />
        <Route path="/scan/:scanId" element={<ScanPage />} />
        <Route path="/scan/:scanId/findings" element={<FindingsPage />} />
        <Route path="/scan/:scanId/findings/:findingId" element={<FindingDetailPage />} />
        <Route path="/scan/:scanId/graph" element={<GraphPage />} />
        <Route path="/scan/:scanId/report" element={<ReportPage />} />
        <Route path="/tools" element={<ToolsPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="*" element={<div className="p-16 text-center text-slate-500">Not found</div>} />
      </Route>
    </Routes>
  );
}
