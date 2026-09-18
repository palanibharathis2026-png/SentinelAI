import { useEffect, useState } from "react";
import { Route, Routes } from "react-router-dom";
import { getAuth, onAuthChange } from "./auth.js";
import Layout from "./components/Layout.jsx";
import Landing from "./pages/Landing.jsx";
import Login from "./pages/Login.jsx";
import StaffPortal from "./pages/StaffPortal.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import Employees from "./pages/Employees.jsx";
import EmployeeDetail from "./pages/EmployeeDetail.jsx";
import Incident from "./pages/Incident.jsx";
import Model from "./pages/Model.jsx";
import RiskLab from "./pages/RiskLab.jsx";
import ThreatMapPage from "./pages/ThreatMapPage.jsx";

export default function App() {
  const [auth, setAuthState] = useState(getAuth);
  useEffect(() => onAuthChange(() => setAuthState(getAuth())), []);

  // Nothing is visible until someone logs in: admins get the SOC, staff get their workspace.
  if (!auth) return <Login />;
  if (auth.role === "staff") return <StaffPortal />;

  return (
    <Layout user={auth.name}>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/soc" element={<Dashboard />} />
        <Route path="/map" element={<ThreatMapPage />} />
        <Route path="/lab" element={<RiskLab />} />
        <Route path="/employees" element={<Employees />} />
        <Route path="/employees/:id" element={<EmployeeDetail />} />
        <Route path="/incidents/:id" element={<Incident />} />
        <Route path="/model" element={<Model />} />
        <Route path="*" element={<Landing />} />
      </Routes>
    </Layout>
  );
}
