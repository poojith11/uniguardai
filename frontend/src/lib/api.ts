// UNIGUARD AI - Frontend API Service Layer
// Connects to FastAPI Backend running Phase 3I ML Pipeline

export interface FlowRecord {
  flow_id: string;
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  protocol: string;
  packet_count: number;
  byte_count: number;
  duration_seconds: number;
  predicted_class: 'BENIGN' | 'DDOS' | 'RECON_SCAN' | 'C2_BEACONING';
  is_threat: boolean;
  severity: 'BENIGN' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  anomaly_score: number;
  is_anomaly: boolean;
  probabilities?: Record<string, number>;
  features?: Record<string, number>;
}

export interface PCAPAnalysisResponse {
  pcap_filename: string;
  file_size_bytes: number;
  total_packets: number;
  total_flows: number;
  evaluated_flows: number;
  benign_flows: number;
  threat_flows: number;
  anomaly_flows: number;
  threat_breakdown: {
    BENIGN: number;
    C2_BEACONING: number;
    DDOS: number;
    RECON_SCAN: number;
  };
  flows: FlowRecord[];
  timing_ms: {
    parse_time_ms: number;
    aggregation_time_ms: number;
    inference_time_ms: number;
    total_time_ms: number;
  };
}

export interface ModelInfoResponse {
  status: string;
  model_metadata: {
    model_name: string;
    model_version: string;
    feature_count: number;
    features: string[];
    supervised_algorithm: string;
    anomaly_algorithm: string;
    validation_metrics?: {
      accuracy: number;
      macro_f1: number;
    };
    unseen_test_metrics?: {
      accuracy: number;
      macro_f1: number;
      benign_false_positive_rate: number;
      isolation_forest_threat_recall: number;
      mean_inference_latency_ms: number;
      throughput_flows_per_sec: number;
    };
    feature_importance?: Record<string, number>;
  };
  training_manifest?: {
    phase: string;
    training_captures: string[];
    validation_captures: string[];
    unseen_test_captures: string[];
    train_flow_count: number;
    test_flow_count: number;
  };
  supported_classes: string[];
  unsupported_classes: string[];
  feature_count: number;
  architecture: {
    tier_1: string;
    tier_2: string;
    feature_pipeline: string;
  };
}

export interface SamplePCAP {
  filename: string;
  size_mb: number;
  path: string;
}

/**
 * Returns the configured API base URL (e.g. https://api.yourdomain.com in production)
 * or empty string in development to leverage the Vite proxy (/api).
 */
export const getApiBaseUrl = (): string => {
  const envUrl = import.meta.env.VITE_BACKEND_URL || import.meta.env.VITE_API_BASE_URL || '';
  return envUrl.replace(/\/+$/, '');
};

/**
 * Constructs a fully-qualified or relative API URL.
 */
export const getApiUrl = (endpoint: string): string => {
  const base = getApiBaseUrl();
  const path = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  return base ? `${base}${path}` : path;
};

export const fetchModelInfo = async (): Promise<ModelInfoResponse | null> => {
  try {
    const res = await fetch(getApiUrl('/api/ml/model-info'));
    if (!res.ok) return null;
    return await res.json();
  } catch (err) {
    console.error('Failed to fetch model info:', err);
    return null;
  }
};


export const fetchSamplePCAPs = async (): Promise<SamplePCAP[]> => {
  try {
    const res = await fetch(getApiUrl('/api/ml/samples'));
    if (!res.ok) return [];
    const data = await res.json();
    return data.samples || [];
  } catch (err) {
    console.error('Failed to fetch sample PCAPs:', err);
    return [];
  }
};

export const analyzeUploadedPCAP = async (file: File, maxFlows: number = 300): Promise<PCAPAnalysisResponse> => {
  if (file.size > 50 * 1024 * 1024) {
    throw new Error('File exceeds maximum upload limit of 50 MB. Please choose a smaller capture slice.');
  }

  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await fetch(getApiUrl(`/api/analyze/pcap?max_flows=${maxFlows}`), {
      method: 'POST',
      body: formData,
    });

    if (!res.ok) {
      if (res.status === 429) {
        const retryAfter = res.headers.get('Retry-After') || '60';
        throw new Error(`API rate limit reached. Please wait ${retryAfter} seconds before submitting another analysis.`);
      }
      if (res.status === 413) {
        throw new Error('Upload payload too large. Maximum supported PCAP size is 50 MB.');
      }
      const errorData = await res.json().catch(() => ({ detail: 'Analysis failed' }));
      throw new Error(errorData.detail || `Upload analysis failed (HTTP ${res.status})`);
    }

    return await res.json();
  } catch (err: any) {
    if (err.message && !err.message.includes('fetch')) {
      throw err;
    }
    throw new Error('Unable to connect to UNIGUARD AI backend. Please verify that the API server is running on port 8000.');
  }
};

export const analyzeSamplePCAP = async (filename: string, maxFlows: number = 300): Promise<PCAPAnalysisResponse> => {
  try {
    const res = await fetch(getApiUrl(`/api/analyze/sample-pcap?filename=${encodeURIComponent(filename)}&max_flows=${maxFlows}`), {
      method: 'POST',
    });

    if (!res.ok) {
      if (res.status === 429) {
        const retryAfter = res.headers.get('Retry-After') || '60';
        throw new Error(`API rate limit reached. Please wait ${retryAfter} seconds before submitting another request.`);
      }
      const errorData = await res.json().catch(() => ({ detail: 'Sample analysis failed' }));
      throw new Error(errorData.detail || `Sample analysis failed (HTTP ${res.status})`);
    }

    return await res.json();
  } catch (err: any) {
    if (err.message && !err.message.includes('fetch')) {
      throw err;
    }
    throw new Error('Backend communication error. Please ensure UNIGUARD AI backend is active.');
  }
};

