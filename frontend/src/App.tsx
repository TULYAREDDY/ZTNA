import { Route, Routes } from "react-router-dom";
import { Background } from "@/components/layout/Background";
import { Sidebar } from "@/components/layout/Sidebar";
import { TopBar } from "@/components/layout/TopBar";
import { Dashboard } from "@/pages/Dashboard";
import { SessionsPage } from "@/pages/SessionsPage";
import { LabPage } from "@/pages/LabPage";
import { MlPage } from "@/pages/MlPage";
import { EventStreamProvider, useEventStream } from "@/hooks/useEventStream";

function Shell() {
  const { connected } = useEventStream();
  return (
    <div className="flex min-h-screen">
      <Background />
      <Sidebar />
      <main className="flex-1 min-w-0 flex flex-col">
        <TopBar connected={connected} />
        <div className="p-6 flex-1">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/sessions" element={<SessionsPage />} />
            <Route path="/lab" element={<LabPage />} />
            <Route path="/ml" element={<MlPage />} />
          </Routes>
        </div>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <EventStreamProvider>
      <Shell />
    </EventStreamProvider>
  );
}
