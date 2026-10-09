import React, { createContext, useContext, useState, useEffect } from 'react';
import type { PCAPAnalysisResponse, ModelInfoResponse, SamplePCAP } from './api';
import { fetchModelInfo, fetchSamplePCAPs, analyzeSamplePCAP, analyzeUploadedPCAP } from './api';

interface TrafficContextType {
  analysis: PCAPAnalysisResponse | null;
  modelInfo: ModelInfoResponse | null;
  samples: SamplePCAP[];
  isLoading: boolean;
  error: string | null;
  runSampleAnalysis: (filename: string) => Promise<void>;
  runUploadAnalysis: (file: File) => Promise<void>;
  clearAnalysis: () => void;
}

const TrafficContext = createContext<TrafficContextType | undefined>(undefined);

export const TrafficProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [analysis, setAnalysis] = useState<PCAPAnalysisResponse | null>(null);
  const [modelInfo, setModelInfo] = useState<ModelInfoResponse | null>(null);
  const [samples, setSamples] = useState<SamplePCAP[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchModelInfo().then(setModelInfo);
    fetchSamplePCAPs().then(setSamples);
  }, []);

  const runSampleAnalysis = async (filename: string) => {
    setIsLoading(true);
    setError(null);
    try {
      const result = await analyzeSamplePCAP(filename);
      setAnalysis(result);
    } catch (err: any) {
      setError(err.message || 'Failed to analyze sample capture');
    } finally {
      setIsLoading(false);
    }
  };

  const runUploadAnalysis = async (file: File) => {
    setIsLoading(true);
    setError(null);
    try {
      const result = await analyzeUploadedPCAP(file);
      setAnalysis(result);
    } catch (err: any) {
      setError(err.message || 'Failed to analyze uploaded PCAP');
    } finally {
      setIsLoading(false);
    }
  };

  const clearAnalysis = () => {
    setAnalysis(null);
    setError(null);
  };

  return (
    <TrafficContext.Provider
      value={{
        analysis,
        modelInfo,
        samples,
        isLoading,
        error,
        runSampleAnalysis,
        runUploadAnalysis,
        clearAnalysis,
      }}
    >
      {children}
    </TrafficContext.Provider>
  );
};

export const useTraffic = () => {
  const context = useContext(TrafficContext);
  if (!context) {
    throw new Error('useTraffic must be used within a TrafficProvider');
  }
  return context;
};
