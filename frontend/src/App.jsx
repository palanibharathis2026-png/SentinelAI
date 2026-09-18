import { Route, Routes } from "react-router-dom";
import Layout from "./components/Layout.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import Employees from "./pages/Employees.jsx";
import EmployeeDetail from "./pages/EmployeeDetail.jsx";
import Incident from "./pages/Incident.jsx";
import Model from "./pages/Model.jsx";

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/employees" element={<Employees />} />
        <Route path="/employees/:id" element={<EmployeeDetail />} />
        <Route path="/incidents/:id" element={<Incident />} />
        <Route path="/model" element={<Model />} />
      </Routes>
    </Layout>
  );
}
