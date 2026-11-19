"use client";

import React, { useState, useEffect } from 'react';
import {
  Shield,
  Activity,
  AlertTriangle,
  Globe,
  Layers,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Search,
  MessageSquare,
  Clock,
  User,
  ArrowRight,
  Sparkles,
  Zap,
  Info,
  Terminal,
  Filter,
  BarChart2,
  TrendingUp,
  Cpu
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  LineChart,
  Line,
  Legend
} from 'recharts';

interface AnalyticsData {
  overview: {
    total_requests_analyzed: number;
    total_obfuscated_attempts: number;
    total_multilingual_attempts: number;
    total_multi_turn_attacks: number;
    total_blocked_requests: number;
    total_allowed_requests: number;
    total_conversations: number;
    suspicious_conversations: number;
    conversation_risk_distribution: Record<string, number>;
  };
  technique_breakdown: Array<{ technique: string; count: number }>;
  risk_comparison: {
    conversation_risk: Record<string, number>;
    individual_risk: Record<string, number>;
  };
  timeline_data: Array<{
    date: string;
    allowed: number;
    blocked: number;
    multilingual: number;
    obfuscated: number;
  }>;
}

interface ConversationItem {
  conversation_id: string;
  user_id: number | null;
  username: string;
  department: string;
  role?: string;
  user_type?: string;
  authentication_status?: string;
  authorization_status?: string;
  user_identity_label?: string;
  total_turns: number;
  last_activity: string;
  final_decision: string;
  final_cumulative_risk: string;
  has_obfuscation: boolean;
  has_multilingual: boolean;
  has_multi_turn_attack: boolean;
}

interface MessageTimelineItem {
  id: number;
  turn_index: number;
  request_log_id: string;
  timestamp: string;
  raw_message: string;
  normalized_message: string;
  detected_language: string;
  detected_techniques: string[];
  indicators: {
    has_unicode_homoglyphs?: boolean;
    unicode_chars_count?: number;
    has_scrambled_spaced_text?: boolean;
    has_emoji_obfuscation?: boolean;
    emoji_count?: number;
    is_multilingual?: boolean;
    detected_language?: string;
    obfuscation_score?: number;
    user_type?: string;
    authentication_status?: string;
    authorization_status?: string;
    user_identity_label?: string;
  };
  individual_risk: string;
  individual_risk_score: number;
  cumulative_risk: string;
  cumulative_risk_score: number;
  decision: string;
  enforcement_action: string;
  detection_reason: string;
  detection_layer: string;
  is_attack_turn: boolean;
  user_type?: string;
  authentication_status?: string;
  authorization_status?: string;
  user_identity_label?: string;
  username?: string;
  department?: string;
  role?: string;
}

const TECHNIQUE_COLORS = [
  '#06b6d4', // Cyan
  '#f59e0b', // Amber
  '#ec4899', // Pink
  '#8b5cf6', // Violet
  '#3b82f6', // Blue
  '#f43f5e'  // Rose
];

const RISK_BADGES: Record<string, string> = {
  CRITICAL: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
  HIGH: 'bg-red-500/10 text-red-400 border-red-500/30',
  MEDIUM: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
  LOW: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
  INFORMATIONAL: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
};

const LANGUAGE_LABELS: Record<string, string> = {
  en: 'EN (English)',
  es: 'ES (Spanish)',
  fr: 'FR (French)',
  de: 'DE (German)',
  ru: 'RU (Russian)',
  zh: 'ZH (Chinese)',
  ar: 'AR (Arabic)',
  ja: 'JA (Japanese)'
};

export default function AdvancedPromptInjectionOverview() {
  const [token, setToken] = useState<string | null>(null);
  const [analytics, setAnalytics] = useState<AnalyticsData | null>(null);
  const [conversations, setConversations] = useState<ConversationItem[]>([]);
  const [selectedConvId, setSelectedConvId] = useState<string | null>(null);
  const [conversationDetails, setConversationDetails] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [riskFilter, setRiskFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');

  const [authError, setAuthError] = useState<string | null>(null);

  useEffect(() => {
    const saved = localStorage.getItem('llmshield_token');
    if (saved) {
      setToken(saved);
    } else {
      setLoading(false);
      setAuthError('SOC Analyst authentication required to access centralized conversation intelligence.');
    }
  }, []);

  const handleDevSocLogin = async () => {
    try {
      setLoading(true);
      const res = await fetch('http://127.0.0.1:8000/api/auth/demo-login/soc.admin', {
        method: 'POST'
      });
      if (res.ok) {
        const data = await res.json();
        localStorage.setItem('llmshield_token', data.token);
        localStorage.setItem('llmshield_user', JSON.stringify(data.user));
        setToken(data.token);
        setAuthError(null);
      } else {
        setAuthError('Demo SOC login unavailable. Please log in with valid credentials.');
      }
    } catch (err) {
      setAuthError('Failed to connect to gateway for authentication.');
    } finally {
      setLoading(false);
    }
  };

  const loadData = async () => {
    if (!token) return;
    setLoading(true);
    try {
      // 1. Fetch Analytics
      const aRes = await fetch('http://127.0.0.1:8000/api/conversations/analytics', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (aRes.ok) {
        const aData = await aRes.json();
        setAnalytics(aData);
        setAuthError(null);
      } else if (aRes.status === 403) {
        setAuthError('Forbidden: This account does not possess the SOC_ANALYST role required for aggregated investigations.');
      } else if (aRes.status === 401) {
        setAuthError('Session expired or invalid. Please sign in again.');
        localStorage.removeItem('llmshield_token');
        setToken(null);
      }

      // 2. Fetch Conversations
      const cRes = await fetch('http://127.0.0.1:8000/api/conversations', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (cRes.ok) {
        const cData = await cRes.json();
        setConversations(cData);
        if (cData.length > 0 && !selectedConvId) {
          setSelectedConvId(cData[0].conversation_id);
        }
      }
    } catch (err) {
      console.error('Error loading advanced prompt detection data:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadConversationDetails = async (convId: string) => {
    if (!token) return;
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/conversations/${encodeURIComponent(convId)}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setConversationDetails(data);
      }
    } catch (err) {
      console.error('Error loading conversation details:', err);
    }
  };

  useEffect(() => {
    if (token) {
      loadData();
      const interval = setInterval(loadData, 8000);
      return () => clearInterval(interval);
    }
  }, [token]);

  useEffect(() => {
    if (selectedConvId && token) {
      loadConversationDetails(selectedConvId);
    }
  }, [selectedConvId, token]);

  const filteredConversations = conversations.filter((c) => {
    const matchesSearch =
      c.conversation_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.department.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesRisk = riskFilter === 'ALL' || c.final_cumulative_risk === riskFilter;
    const matchesStatus = statusFilter === 'ALL' || c.final_decision === statusFilter;
    return matchesSearch && matchesRisk && matchesStatus;
  });

  const overview = analytics?.overview || {
    total_requests_analyzed: 0,
    total_obfuscated_attempts: 0,
    total_multilingual_attempts: 0,
    total_multi_turn_attacks: 0,
    total_blocked_requests: 0,
    total_allowed_requests: 0,
    total_conversations: 0,
    suspicious_conversations: 0,
    conversation_risk_distribution: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 }
  };

  const riskComparisonData = [
    {
      level: 'LOW',
      SingleMessageRisk: analytics?.risk_comparison?.individual_risk?.LOW || 0,
      CumulativeRisk: analytics?.risk_comparison?.conversation_risk?.LOW || 0
    },
    {
      level: 'MEDIUM',
      SingleMessageRisk: analytics?.risk_comparison?.individual_risk?.MEDIUM || 0,
      CumulativeRisk: analytics?.risk_comparison?.conversation_risk?.MEDIUM || 0
    },
    {
      level: 'HIGH',
      SingleMessageRisk: analytics?.risk_comparison?.individual_risk?.HIGH || 0,
      CumulativeRisk: analytics?.risk_comparison?.conversation_risk?.HIGH || 0
    },
    {
      level: 'CRITICAL',
      SingleMessageRisk: analytics?.risk_comparison?.individual_risk?.CRITICAL || 0,
      CumulativeRisk: analytics?.risk_comparison?.conversation_risk?.CRITICAL || 0
    }
  ];

  return (
    <div className="space-y-12">
      {/* SECTION HEADER */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-mono uppercase tracking-widest mb-2">
            <Sparkles className="w-3.5 h-3.5" /> Phase 6 Intelligence
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-3">
            Advanced Prompt Injection & Obfuscation Telemetry
          </h1>
          <p className="text-slate-400 text-xs sm:text-sm mt-1 max-w-3xl">
            Real-time multi-layer behavioral analytics distinguishing obfuscation indicators from confirmed policy decisions.
            Features homoglyph normalization, emoji de-spacing, multilingual translation, and multi-turn progressive injection interception.
          </p>
        </div>

        <button
          onClick={loadData}
          disabled={loading}
          className="self-start md:self-auto flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-900 border border-slate-700 hover:border-cyan-500/50 text-slate-300 hover:text-white text-xs font-mono transition-all disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
          <span>Sync Real-Time Telemetry</span>
        </button>
      </div>

      {/* AUTHENTICATION / ACCESS BANNER */}
      {authError && (
        <div className="p-4 rounded-xl bg-amber-950/30 border border-amber-800/50 text-amber-300 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 text-amber-400" />
            <span>{authError}</span>
          </div>
          <div className="flex items-center gap-2">
            <a
              href="/login"
              className="px-3 py-1 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 text-amber-200 font-mono text-[11px] transition-all"
            >
              Sign In to SOC
            </a>
            <button
              onClick={handleDevSocLogin}
              className="px-3 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-600 text-slate-200 font-mono text-[11px] transition-all"
            >
              Dev Quick Connect
            </button>
          </div>
        </div>
      )}
      <section>
        <h2 className="text-xs font-mono text-cyan-400 uppercase tracking-widest mb-4 flex items-center gap-2">
          <Activity className="w-4 h-4" /> 6.1 Advanced Security Overview Metrics
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
          {/* Card 1 */}
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 backdrop-blur-sm">
            <div className="text-[11px] text-slate-400 font-mono uppercase">Analyzed</div>
            <div className="text-xl font-bold text-white mt-1">{overview.total_requests_analyzed}</div>
            <div className="text-[10px] text-slate-500 mt-1">Total requests</div>
          </div>

          {/* Card 2 */}
          <div className="p-4 rounded-xl bg-slate-900/60 border border-amber-500/20 bg-amber-500/5 backdrop-blur-sm">
            <div className="text-[11px] text-amber-400 font-mono uppercase">Obfuscated</div>
            <div className="text-xl font-bold text-amber-300 mt-1">{overview.total_obfuscated_attempts}</div>
            <div className="text-[10px] text-amber-500/80 mt-1">Homoglyphs/Spaced</div>
          </div>

          {/* Card 3 */}
          <div className="p-4 rounded-xl bg-slate-900/60 border border-cyan-500/20 bg-cyan-500/5 backdrop-blur-sm">
            <div className="text-[11px] text-cyan-400 font-mono uppercase">Multilingual</div>
            <div className="text-xl font-bold text-cyan-300 mt-1">{overview.total_multilingual_attempts}</div>
            <div className="text-[10px] text-cyan-500/80 mt-1">Non-English queries</div>
          </div>

          {/* Card 4 */}
          <div className="p-4 rounded-xl bg-slate-900/60 border border-purple-500/20 bg-purple-500/5 backdrop-blur-sm">
            <div className="text-[11px] text-purple-400 font-mono uppercase">Multi-Turn</div>
            <div className="text-xl font-bold text-purple-300 mt-1">{overview.total_multi_turn_attacks}</div>
            <div className="text-[10px] text-purple-500/80 mt-1">Progressive attacks</div>
          </div>

          {/* Card 5 */}
          <div className="p-4 rounded-xl bg-slate-900/60 border border-rose-500/20 bg-rose-500/5 backdrop-blur-sm">
            <div className="text-[11px] text-rose-400 font-mono uppercase">Blocked</div>
            <div className="text-xl font-bold text-rose-400 mt-1">{overview.total_blocked_requests}</div>
            <div className="text-[10px] text-rose-500/80 mt-1">Policy enforcement</div>
          </div>

          {/* Card 6 */}
          <div className="p-4 rounded-xl bg-slate-900/60 border border-emerald-500/20 bg-emerald-500/5 backdrop-blur-sm">
            <div className="text-[11px] text-emerald-400 font-mono uppercase">Allowed</div>
            <div className="text-xl font-bold text-emerald-400 mt-1">{overview.total_allowed_requests}</div>
            <div className="text-[10px] text-emerald-500/80 mt-1">Vetted requests</div>
          </div>

          {/* Card 7 */}
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 backdrop-blur-sm">
            <div className="text-[11px] text-slate-400 font-mono uppercase">Conversations</div>
            <div className="text-xl font-bold text-white mt-1">{overview.total_conversations}</div>
            <div className="text-[10px] text-slate-500 mt-1">Unique sessions</div>
          </div>

          {/* Card 8 */}
          <div className="p-4 rounded-xl bg-slate-900/60 border border-red-500/20 bg-red-500/5 backdrop-blur-sm">
            <div className="text-[11px] text-red-400 font-mono uppercase">Suspicious</div>
            <div className="text-xl font-bold text-red-400 mt-1">{overview.suspicious_conversations}</div>
            <div className="text-[10px] text-red-500/80 mt-1">Compounded risk</div>
          </div>
        </div>
      </section>

      {/* 6.2 DETECTION TECHNIQUE BREAKDOWN & 6.5 RISK COMPARISON */}
      <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* TECHNIQUE BREAKDOWN CHART */}
        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800/80 backdrop-blur-sm">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" /> 6.2 Detection Technique Breakdown
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Distribution across 6 evasion vectors tracked by LLMShield
              </p>
            </div>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={analytics?.technique_breakdown || []}
                layout="vertical"
                margin={{ top: 5, right: 30, left: 140, bottom: 5 }}
              >
                <XAxis type="number" stroke="#64748b" fontSize={11} />
                <YAxis
                  type="category"
                  dataKey="technique"
                  stroke="#94a3b8"
                  fontSize={11}
                  width={130}
                  tickFormatter={(val) => (val.length > 20 ? `${val.substring(0, 18)}...` : val)}
                />
                <RechartsTooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    fontSize: '12px',
                    color: '#f8fafc'
                  }}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {(analytics?.technique_breakdown || []).map((_, index) => (
                    <Cell key={`cell-${index}`} fill={TECHNIQUE_COLORS[index % TECHNIQUE_COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* 6.5 RISK COMPARISON: INDIVIDUAL VS CUMULATIVE */}
        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800/80 backdrop-blur-sm">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <BarChart2 className="w-4 h-4 text-purple-400" /> 6.5 Individual vs. Cumulative Risk Distribution
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Demonstrates how low-risk individual turns compound into high cumulative risk
              </p>
            </div>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={riskComparisonData} margin={{ top: 10, right: 20, left: 0, bottom: 5 }}>
                <XAxis dataKey="level" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} />
                <RechartsTooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    fontSize: '12px'
                  }}
                />
                <Legend
                  wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }}
                  iconType="circle"
                />
                <Bar dataKey="SingleMessageRisk" name="Single Message Risk" fill="#06b6d4" radius={[4, 4, 0, 0]} />
                <Bar dataKey="CumulativeRisk" name="Cumulative Session Risk" fill="#a855f7" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </section>

      {/* 6.3 & 6.4 CONVERSATION SECURITY INVESTIGATION (MASTER-DETAIL WORKBENCH) */}
      <section className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-xs font-mono text-cyan-400 uppercase tracking-widest flex items-center gap-2">
              <Terminal className="w-4 h-4" /> 6.3 & 6.4 Conversation Security Investigation
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Select a conversation to inspect raw message payloads, canonical representations, indicators, and cumulative risk escalation.
            </p>
          </div>

          {/* FILTERS */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter by ID / User / Dept..."
                className="pl-8 pr-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-44"
              />
            </div>

            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
              className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Risk Levels</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Statuses</option>
              <option value="BLOCKED">Blocked</option>
              <option value="ALLOWED">Allowed</option>
            </select>
          </div>
        </div>

        {/* WORKBENCH GRID: LIST ON LEFT, DETAIL ON RIGHT */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* LEFT: CONVERSATION LIST (4 COLS) */}
          <div className="lg:col-span-4 rounded-2xl bg-slate-900/60 border border-slate-800/80 p-4 max-h-[720px] overflow-y-auto space-y-2">
            <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-2 px-1">
              Conversations ({filteredConversations.length})
            </div>

            {filteredConversations.length === 0 ? (
              <div className="text-center py-12 text-slate-500 text-xs font-mono">
                No matching conversations found.
              </div>
            ) : (
              filteredConversations.map((c) => {
                const isSelected = selectedConvId === c.conversation_id;
                return (
                  <button
                    key={c.conversation_id}
                    onClick={() => setSelectedConvId(c.conversation_id)}
                    className={`w-full text-left p-3.5 rounded-xl border transition-all ${
                      isSelected
                        ? 'bg-cyan-950/30 border-cyan-500/60 shadow-[0_0_15px_rgba(6,182,212,0.15)]'
                        : 'bg-slate-900/40 border-slate-800 hover:border-slate-700 hover:bg-slate-800/30'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 mb-1.5">
                      <span className="font-mono text-xs font-semibold text-white truncate max-w-[170px]">
                        {c.conversation_id}
                      </span>
                      <span
                        className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                          c.final_decision === 'BLOCKED'
                            ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                            : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                        }`}
                      >
                        {c.final_decision}
                      </span>
                    </div>

                    <div className="mb-2">
                      <div className="flex items-center justify-between text-[11px] text-slate-400 mb-1.5">
                        <span className="flex items-center gap-1 text-slate-300 font-medium">
                          <User className="w-3 h-3 text-slate-500" />
                          {c.username && c.username !== 'Unauthenticated' ? `${c.username} (${c.department})` : 'External Requester'}
                        </span>
                        <span className="font-mono text-slate-500">{c.total_turns} {c.total_turns === 1 ? 'turn' : 'turns'}</span>
                      </div>
                      <div className="flex items-center gap-1">
                        <span className={`text-[9px] font-mono px-2 py-0.5 rounded border font-semibold tracking-wide ${
                          c.user_type === 'INTERNAL_USER' || (c.user_id && c.username !== 'Unauthenticated')
                            ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40'
                            : 'bg-amber-500/15 text-amber-300 border-amber-500/40'
                        }`}>
                          {c.user_identity_label || (c.user_type === 'INTERNAL_USER' || (c.user_id && c.username !== 'Unauthenticated') ? 'INTERNAL USER – AUTHENTICATED EMPLOYEE' : 'EXTERNAL USER – UNAUTHORIZED')}
                        </span>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-1.5 pt-1 border-t border-slate-800/60">
                      <span
                        className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
                          RISK_BADGES[c.final_cumulative_risk] || 'bg-slate-800 text-slate-400 border-slate-700'
                        }`}
                      >
                        {c.final_cumulative_risk} RISK
                      </span>

                      {c.has_obfuscation && (
                        <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/30">
                          Obfuscated
                        </span>
                      )}
                      {c.has_multilingual && (
                        <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
                          Multilingual
                        </span>
                      )}
                      {c.has_multi_turn_attack && (
                        <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/30">
                          Multi-Turn
                        </span>
                      )}
                    </div>
                  </button>
                );
              })
            )}
          </div>

          {/* RIGHT: CHRONOLOGICAL MESSAGE SEQUENCE & INVESTIGATION DETAIL (8 COLS) */}
          <div className="lg:col-span-8 rounded-2xl bg-slate-900/60 border border-slate-800/80 p-6 min-h-[500px]">
            {!conversationDetails ? (
              <div className="flex flex-col items-center justify-center py-20 text-slate-500 space-y-2">
                <MessageSquare className="w-8 h-8 opacity-40 text-cyan-400" />
                <span className="text-xs font-mono">Select a conversation to view the investigation timeline</span>
              </div>
            ) : (
              <div className="space-y-6">
                {/* CONVERSATION SUMMARY HEADER */}
                <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-bold text-white font-mono">{conversationDetails.conversation_id}</span>
                      <span
                        className={`text-xs font-mono px-2 py-0.5 rounded border ${
                          conversationDetails.final_decision === 'BLOCKED'
                            ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                            : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                        }`}
                      >
                        {conversationDetails.final_decision}
                      </span>
                      {/* VERIFIED IDENTITY CLASSIFICATION BADGE */}
                      <span
                        className={`text-[10px] font-mono px-2.5 py-0.5 rounded border font-semibold tracking-wider uppercase ${
                          conversationDetails.user_type === 'INTERNAL_USER' || (conversationDetails.user_id && conversationDetails.username !== 'Unauthenticated')
                            ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40'
                            : 'bg-amber-500/15 text-amber-300 border-amber-500/40'
                        }`}
                      >
                        {conversationDetails.user_identity_label || (conversationDetails.user_type === 'INTERNAL_USER' || (conversationDetails.user_id && conversationDetails.username !== 'Unauthenticated') ? 'INTERNAL USER – AUTHENTICATED EMPLOYEE' : 'EXTERNAL USER – UNAUTHORIZED')}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-x-4 gap-y-1 text-xs text-slate-400 mt-2.5 pt-2 border-t border-slate-800/80 font-mono">
                      <div>
                        <span className="text-[10px] text-slate-500 block">USER TYPE</span>
                        <strong className="text-slate-200">{conversationDetails.user_type || (conversationDetails.user_id ? 'INTERNAL_USER' : 'EXTERNAL_USER')}</strong>
                      </div>
                      <div>
                        <span className="text-[10px] text-slate-500 block">AUTHENTICATION</span>
                        <strong className="text-slate-200">{conversationDetails.authentication_status || (conversationDetails.user_id ? 'AUTHENTICATED' : 'UNAUTHENTICATED')}</strong>
                      </div>
                      <div>
                        <span className="text-[10px] text-slate-500 block">AUTHORIZATION</span>
                        <strong className={conversationDetails.authorization_status === 'UNAUTHORIZED' ? 'text-amber-400' : 'text-slate-300'}>
                          {conversationDetails.authorization_status || (conversationDetails.user_id ? 'NOT_EVALUATED' : 'UNAUTHORIZED')}
                        </strong>
                      </div>
                      <div>
                        <span className="text-[10px] text-slate-500 block">IDENTITY</span>
                        <strong className="text-cyan-300">
                          {conversationDetails.username && conversationDetails.username !== 'Unauthenticated'
                            ? `${conversationDetails.username} (${conversationDetails.department})`
                            : 'External Visitor'}
                        </strong>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    <div className="text-right">
                      <div className="text-[10px] text-slate-500 font-mono uppercase">Cumulative Risk Score</div>
                      <div className="text-lg font-mono font-bold text-cyan-400">
                        {conversationDetails.final_cumulative_score} / 1.00
                      </div>
                    </div>
                    <span
                      className={`text-xs font-mono px-2.5 py-1.5 rounded-lg border font-semibold ${
                        RISK_BADGES[conversationDetails.final_cumulative_risk] || 'bg-slate-800 text-slate-300'
                      }`}
                    >
                      {conversationDetails.final_cumulative_risk}
                    </span>
                  </div>
                </div>

                {/* TIMELINE OF MESSAGES */}
                <div className="space-y-6 relative before:absolute before:inset-0 before:left-5 before:w-0.5 before:bg-slate-800 before:z-0">
                  {conversationDetails.timeline?.map((msg: MessageTimelineItem, idx: number) => {
                    const isBlocked = msg.decision === 'BLOCKED';
                    return (
                      <div key={msg.id || idx} className="relative z-10 pl-12">
                        {/* TURN BADGE CIRCLE */}
                        <div
                          className={`absolute left-2.5 -translate-x-1/2 top-4 w-6 h-6 rounded-full flex items-center justify-center font-mono text-[11px] font-bold border ${
                            isBlocked
                              ? 'bg-rose-500 text-white border-rose-400 shadow-[0_0_10px_rgba(244,63,94,0.4)]'
                              : 'bg-slate-800 text-cyan-300 border-cyan-500/40'
                          }`}
                        >
                          {msg.turn_index}
                        </div>

                        {/* MESSAGE CARD */}
                        <div
                          className={`p-5 rounded-xl border backdrop-blur-sm transition-all ${
                            isBlocked
                              ? 'bg-rose-950/20 border-rose-500/40 shadow-[0_0_20px_rgba(244,63,94,0.1)]'
                              : 'bg-slate-900/80 border-slate-800 hover:border-slate-700'
                          }`}
                        >
                          {/* CARD HEADER */}
                          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 pb-3 mb-3">
                            <div className="flex items-center gap-2">
                              <span className="text-xs font-bold font-mono text-white">
                                Turn {msg.turn_index}
                              </span>
                              <span className="text-[11px] font-mono text-slate-500">
                                {new Date(msg.timestamp).toLocaleTimeString()}
                              </span>
                              {/* LANGUAGE BADGE */}
                              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/30">
                                {LANGUAGE_LABELS[msg.detected_language] || msg.detected_language?.toUpperCase() || 'EN'}
                              </span>

                              {/* USER IDENTITY BADGE */}
                              <span className={`text-[9px] font-mono px-2 py-0.5 rounded border ${
                                msg.user_type === 'INTERNAL_USER' || (msg.username && msg.username !== 'Unauthenticated')
                                  ? 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30'
                                  : 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                              }`}>
                                {msg.user_identity_label || (msg.user_type === 'INTERNAL_USER' || (msg.username && msg.username !== 'Unauthenticated') ? 'INTERNAL USER – AUTHENTICATED EMPLOYEE' : 'EXTERNAL USER – UNAUTHORIZED')}
                              </span>
                            </div>

                            <div className="flex items-center gap-2 font-mono text-xs">
                              <span className="text-slate-400 text-[11px]">
                                Turn Risk: <strong className="text-white">{msg.individual_risk} ({msg.individual_risk_score})</strong>
                              </span>
                              <ArrowRight className="w-3 h-3 text-slate-600" />
                              <span className="text-slate-400 text-[11px]">
                                Cumulative: <strong className="text-cyan-400">{msg.cumulative_risk} ({msg.cumulative_risk_score})</strong>
                              </span>
                              <span
                                className={`text-[10px] px-2 py-0.5 rounded border ${
                                  isBlocked
                                    ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                                    : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                                }`}
                              >
                                {msg.decision}
                              </span>
                            </div>
                          </div>

                          {/* RAW MESSAGE VS NORMALIZED CANONICAL */}
                          <div className="space-y-3">
                            <div>
                              <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-1">
                                Raw Inbound Message Payload
                              </div>
                              <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800/80 font-mono text-xs text-slate-200 break-words whitespace-pre-wrap">
                                {msg.raw_message}
                              </div>
                            </div>

                            {msg.normalized_message && msg.normalized_message !== msg.raw_message && (
                              <div>
                                <div className="text-[10px] font-mono text-cyan-400/80 uppercase tracking-wider mb-1 flex items-center gap-1.5">
                                  <Sparkles className="w-3 h-3 text-cyan-400" /> Normalized Canonical Form (Homoglyphs Stripped / De-Spaced / Translated)
                                </div>
                                <div className="p-2.5 rounded-lg bg-cyan-950/20 border border-cyan-800/40 font-mono text-xs text-cyan-200 break-words whitespace-pre-wrap">
                                  {msg.normalized_message}
                                </div>
                              </div>
                            )}
                          </div>

                          {/* INDICATORS & DETECTION DETAILS */}
                          <div className="mt-4 pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-3 text-xs">
                            {/* INDICATOR FLAGS (SEPARATE FROM DECISION AS REQUIRED BY 6.7) */}
                            <div className="flex flex-wrap items-center gap-1.5">
                              <span className="text-[10px] font-mono text-slate-500 mr-1">Indicators:</span>
                              {msg.indicators?.has_unicode_homoglyphs && (
                                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/30">
                                  Homoglyphs ({msg.indicators.unicode_chars_count})
                                </span>
                              )}
                              {msg.indicators?.has_scrambled_spaced_text && (
                                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-orange-500/10 text-orange-300 border border-orange-500/30">
                                  Spaced/Scrambled
                                </span>
                              )}
                              {msg.indicators?.emoji_count && msg.indicators.emoji_count > 0 ? (
                                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                                  msg.indicators?.has_emoji_obfuscation
                                    ? 'bg-rose-500/10 text-rose-300 border-rose-500/30'
                                    : 'bg-slate-800 text-slate-300 border-slate-700'
                                }`}>
                                  Emojis ({msg.indicators.emoji_count}) {msg.indicators?.has_emoji_obfuscation ? '⚠️ Obfuscation' : '✓ Benign'}
                                </span>
                              ) : null}
                              {msg.indicators?.is_multilingual && (
                                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/30">
                                  Non-English ({msg.indicators.detected_language})
                                </span>
                              )}
                              {msg.is_attack_turn && (
                                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/30">
                                  Escalation Attack Turn
                                </span>
                              )}
                            </div>

                            {/* ENFORCEMENT & LAYER */}
                            <div className="flex items-center gap-2 font-mono text-[11px]">
                              <span className="text-slate-500">Layer:</span>
                              <span className="text-cyan-400 font-semibold">{msg.detection_layer}</span>
                              <span className="text-slate-500">Action:</span>
                              <span className={isBlocked ? 'text-rose-400 font-semibold' : 'text-emerald-400 font-semibold'}>
                                {msg.enforcement_action}
                              </span>
                            </div>
                          </div>

                          {/* REASON */}
                          {msg.detection_reason && (
                            <div className="mt-2 text-[11px] text-slate-400 font-mono bg-slate-950/40 p-2 rounded border border-slate-800/60">
                              <span className="text-slate-500 font-bold">Reason: </span>
                              {msg.detection_reason}
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        </div>
      </section>
    </div>
  );
}
