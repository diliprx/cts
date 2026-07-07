import React, { useState, useRef } from 'react';
import { Upload, FileCode, CheckCircle2, AlertCircle } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs) {
  return twMerge(clsx(inputs));
}

const VALID_EXTENSIONS = ['.js', '.jsx', '.mjs', '.ts', '.tsx', '.php', '.phtml', '.py', '.pyw', '.txt'];

export default function UploadCard({ onAnalyze, error }) {
  const [isDragging, setIsDragging] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [multiLine, setMultiLine] = useState(true);
  const fileInputRef = useRef(null);

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const validateFile = (file) => {
    if (!file) return false;
    const ext = '.' + file.name.split('.').pop().toLowerCase();
    return VALID_EXTENSIONS.includes(ext);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    
    const file = e.dataTransfer.files[0];
    if (validateFile(file)) {
      setSelectedFile(file);
    } else {
      alert('Please upload a valid JavaScript, PHP, or Python file.');
    }
  };

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (validateFile(file)) {
      setSelectedFile(file);
    }
  };

  const handleSubmit = () => {
    if (selectedFile) {
      onAnalyze(selectedFile, multiLine);
    }
  };

  return (
    <div className="w-full">
      <div 
        className={cn(
          "relative overflow-hidden rounded-3xl p-10 transition-all duration-300 ease-out",
          "border-2 border-dashed",
          isDragging 
            ? "border-primary bg-primary/5 scale-[1.02] shadow-apple" 
            : "border-border bg-surface hover:border-primary/50 hover:shadow-apple"
        )}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => !selectedFile && fileInputRef.current?.click()}
      >
        <div className="flex flex-col items-center text-center">
          <motion.div
            initial={false}
            animate={{ 
              scale: isDragging ? 1.1 : 1,
              color: isDragging ? '#007AFF' : '#8E8E93'
            }}
            className="mb-6"
          >
            {selectedFile ? (
              <FileCode className="w-16 h-16 text-primary" />
            ) : (
              <Upload className="w-16 h-16 opacity-80" />
            )}
          </motion.div>
          
          <h3 className="text-2xl font-bold mb-3">
            {selectedFile ? 'File Ready' : 'Upload Your Code'}
          </h3>
          
          <p className="text-textSecondary mb-8 max-w-sm">
            {selectedFile 
              ? `Selected: ${selectedFile.name} (${(selectedFile.size / 1024).toFixed(1)} KB)`
              : 'Drag and drop your file here, or click to browse'
            }
          </p>

          <input
            type="file"
            ref={fileInputRef}
            className="hidden"
            onChange={handleFileChange}
            accept=".js,.jsx,.mjs,.ts,.tsx,.php,.phtml,.py,.pyw,.txt"
          />

          <AnimatePresence>
            {selectedFile && (
              <motion.div
                initial={{ opacity: 0, y: 10, height: 0 }}
                animate={{ opacity: 1, y: 0, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="flex gap-4"
              >
                <button
                  onClick={(e) => { e.stopPropagation(); setSelectedFile(null); }}
                  className="px-6 py-3 font-semibold text-textSecondary bg-background hover:bg-border/50 rounded-xl transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={(e) => { e.stopPropagation(); handleSubmit(); }}
                  className="px-8 py-3 font-semibold text-white bg-primary hover:bg-primary-dark rounded-xl shadow-md transition-all active:scale-95 flex items-center gap-2"
                >
                  Analyze Code
                </button>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>

      <div className="mt-6 flex items-center justify-between p-5 surface rounded-2xl">
        <div>
          <h4 className="font-semibold text-textPrimary">Multi-Line Detection</h4>
          <p className="text-sm text-textSecondary mt-1">Detects vulnerabilities spanning multiple lines of code</p>
        </div>
        
        <label className="relative inline-flex items-center cursor-pointer">
          <input 
            type="checkbox" 
            className="sr-only peer" 
            checked={multiLine}
            onChange={(e) => setMultiLine(e.target.checked)}
          />
          <div className="w-11 h-6 bg-border peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-success"></div>
        </label>
      </div>

      {error && (
        <motion.div 
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="mt-6 p-4 bg-error/10 border border-error/20 rounded-2xl flex items-start gap-3"
        >
          <AlertCircle className="w-5 h-5 text-error shrink-0 mt-0.5" />
          <p className="text-error font-medium text-sm">{error}</p>
        </motion.div>
      )}
    </div>
  );
}
