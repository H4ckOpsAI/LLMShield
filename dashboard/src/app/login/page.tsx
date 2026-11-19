"use client";

import React, { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { Shield, Lock, User, ArrowRight, AlertTriangle, KeyRound, CheckCircle2, Server, UserCheck, ShieldAlert } from "lucide-react";

export default function PortalLoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [demoUsers, setDemoUsers] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("http://127.0.0.1:8000/api/auth/demo-users")
      .then((res) => res.json())
      .then((data) => {
        if (Array.isArray(data)) setDemoUsers(data);
      })
      .catch((err) => console.error("Error loading demo accounts:", err));
  }, []);

  const handleStandardLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) {
      setError("Please provide both username and password.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("http://127.0.0.1:8000/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.trim(), password })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || "Authentication failed.");
      }
      localStorage.setItem("llmshield_token", data.token);
      localStorage.setItem("llmshield_user", JSON.stringify(data.user));
      router.push("/");
    } catch (err: any) {
      setError(err.message || "Failed to authenticate.");
    } finally {
      setLoading(false);
    }
  };

  const handleQuickDemoLogin = async (selectedUsername: string) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("http://127.0.0.1:8000/api/auth/demo-login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: selectedUsername })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || "Demo access failed.");
      }
      localStorage.setItem("llmshield_token", data.token);
      localStorage.setItem("llmshield_user", JSON.stringify(data.user));
      router.push("/");
    } catch (err: any) {
      setError(err.message || "Demo login failed.");
    } finally {
      setLoading(false);
    }
  };

  const employees = demoUsers.filter(u => u.role !== "SOC_ANALYST");
  const socAnalysts = demoUsers.filter(u => u.role === "SOC_ANALYST");

  return (
    <div className="min-h-screen bg-[#030712] text-slate-200 font-sans flex flex-col justify-center items-center p-6 relative overflow-hidden">
      {/* AMBIENT GLOWS */}
      <div className="fixed inset-0 pointer-events-none z-0">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-500/10 rounded-full blur-[128px]"></div>
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-blue-600/10 rounded-full blur-[128px]"></div>
      </div>

      <div className="w-full max-w-md relative z-10 space-y-6">
        {/* LOGO HEADER */}
        <div className="text-center space-y-2">
          <div className="inline-flex p-3 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 shadow-[0_0_20px_rgba(6,182,212,0.2)] mb-2">
            <Shield className="w-8 h-8 text-cyan-400" />
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight">
            LLM<span className="text-cyan-400">Shield</span> Access Portal
          </h1>
          <p className="text-xs font-mono text-slate-400 uppercase tracking-widest">
            Internal Employee & SOC Analyst Authentication
          </p>
        </div>

        {/* LOGIN CARD */}
        <div className="bg-[#070b19]/90 border border-slate-800/80 rounded-2xl p-8 shadow-2xl shadow-black/50 backdrop-blur-xl">
          {error && (
            <div className="mb-6 p-4 rounded-xl bg-rose-950/40 border border-rose-800/60 text-rose-300 text-xs font-mono flex items-start gap-3">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-rose-400" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleStandardLogin} className="space-y-5">
            <div>
              <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-2">
                Corporate Username
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                  <User className="w-4 h-4" />
                </div>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="e.g. alice.smith or soc.admin"
                  className="w-full pl-10 pr-4 py-2.5 bg-slate-900/80 border border-slate-800 rounded-xl text-slate-100 text-sm focus:outline-none focus:border-cyan-500/80 transition font-mono placeholder:text-slate-600"
                />
              </div>
            </div>

            <div>
              <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-2">
                Account Password
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                  <Lock className="w-4 h-4" />
                </div>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full pl-10 pr-4 py-2.5 bg-slate-900/80 border border-slate-800 rounded-xl text-slate-100 text-sm focus:outline-none focus:border-cyan-500/80 transition font-mono placeholder:text-slate-600"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 bg-gradient-to-r from-cyan-500 via-blue-600 to-indigo-600 hover:from-cyan-400 hover:via-blue-500 hover:to-indigo-500 text-white font-medium py-3 rounded-xl shadow-lg shadow-cyan-500/25 transition disabled:opacity-50 text-sm active:scale-95"
            >
              {loading ? (
                <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
              ) : (
                <>
                  <span>Sign In</span>
                  <ArrowRight className="w-4 h-4 text-cyan-200" />
                </>
              )}
            </button>
          </form>

          {/* DEVELOPMENT DEMO ACCOUNTS SELECTOR */}
          {demoUsers.length > 0 && (
            <div className="mt-8 pt-6 border-t border-slate-800/80 space-y-4">
              <div className="text-[10px] font-mono text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
                <KeyRound className="w-3.5 h-3.5 text-cyan-400" /> Fast Demo Access (Development Mode)
              </div>

              {/* SOC Analyst Section */}
              {socAnalysts.length > 0 && (
                <div>
                  <div className="text-[10px] font-mono text-purple-400 uppercase tracking-wider mb-1.5 flex items-center gap-1">
                    <ShieldAlert className="w-3 h-3 text-purple-400" /> Security Operations (SOC)
                  </div>
                  {socAnalysts.map((u) => (
                    <button
                      key={u.username}
                      type="button"
                      onClick={() => handleQuickDemoLogin(u.username)}
                      className="w-full flex items-center justify-between p-2.5 rounded-xl bg-purple-950/20 border border-purple-800/50 hover:border-purple-500 hover:bg-purple-900/30 transition text-left group"
                    >
                      <div>
                        <div className="text-xs font-semibold text-purple-200 group-hover:text-purple-100 transition">
                          {u.full_name}
                        </div>
                        <div className="text-[10px] font-mono text-slate-400">
                          {u.username} • {u.department}
                        </div>
                      </div>
                      <span className="text-[9px] font-mono uppercase px-2 py-0.5 rounded border border-purple-700 bg-purple-900/60 text-purple-300">
                        {u.role}
                      </span>
                    </button>
                  ))}
                </div>
              )}

              {/* Corporate Employees Section */}
              {employees.length > 0 && (
                <div>
                  <div className="text-[10px] font-mono text-cyan-400 uppercase tracking-wider mb-1.5 flex items-center gap-1">
                    <UserCheck className="w-3 h-3 text-cyan-400" /> Corporate Employees
                  </div>
                  <div className="grid grid-cols-1 gap-1.5">
                    {employees.map((u) => (
                      <button
                        key={u.username}
                        type="button"
                        onClick={() => handleQuickDemoLogin(u.username)}
                        className="flex items-center justify-between p-2 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-cyan-500/50 hover:bg-slate-800/50 transition text-left group"
                      >
                        <div>
                          <div className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300 transition">
                            {u.full_name}
                          </div>
                          <div className="text-[10px] font-mono text-slate-500">
                            {u.username} • {u.department}
                          </div>
                        </div>
                        <span className="text-[9px] font-mono uppercase px-2 py-0.5 rounded border border-slate-700 bg-slate-800 text-slate-300">
                          {u.role}
                        </span>
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* BACK TO DASHBOARD */}
        <div className="text-center">
          <a
            href="/"
            className="text-xs font-mono text-slate-400 hover:text-cyan-400 transition inline-flex items-center gap-1.5"
          >
            ← Back to LLMShield SOC Dashboard
          </a>
        </div>
      </div>
    </div>
  );
}
