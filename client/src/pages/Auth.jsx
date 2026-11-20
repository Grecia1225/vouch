import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { postJson, saveSession } from "../api.js";

export default function Auth({ mode, onAuth }) {
  const isRegister = mode === "register";
  const [form, setForm] = useState({ name: "", email: "", password: "" });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const navigate = useNavigate();

  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  const submit = async () => {
    setError("");
    setBusy(true);
    try {
      const data = await postJson(`/auth/${mode}`, form);
      saveSession(data);
      onAuth(data.user);
      navigate("/dashboard");
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card narrow">
      <h2>{isRegister ? "Create your account" : "Welcome back"}</h2>
      {isRegister && <input placeholder="Full name" value={form.name} onChange={set("name")} />}
      <input placeholder="Email" type="email" value={form.email} onChange={set("email")} />
      <input placeholder="Password (min 8 characters)" type="password" value={form.password} onChange={set("password")}
        onKeyDown={(e) => e.key === "Enter" && submit()} />
      {error && <p className="error">{error}</p>}
      <button className="btn" disabled={busy} onClick={submit}>{busy ? "Please wait..." : isRegister ? "Sign up" : "Log in"}</button>
      <p className="muted">
        {isRegister ? <>Already registered? <Link to="/login">Log in</Link></> : <>New here? <Link to="/register">Create an account</Link></>}
      </p>
    </section>
  );
}
