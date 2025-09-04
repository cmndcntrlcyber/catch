// Comprehensive Browser Fingerprinting JavaScript
// This script collects various browser and system characteristics for demonstration purposes

let fingerprintData = {};
let progressValue = 0;
let totalSteps = 0;

// Update progress bar
function updateProgress(step, total, message) {
  const progressBar = document.getElementById('progress-bar');
  const percentage = Math.round((step / total) * 100);
  
  if (progressBar) {
    progressBar.style.width = percentage + '%';
    progressBar.textContent = message;
  }
}

// Hash function for generating fingerprint
async function hashData(data) {
  const encoder = new TextEncoder();
  const dataString = JSON.stringify(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(dataString));
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Collect basic browser information
function collectBrowserInfo() {
  return {
    userAgent: navigator.userAgent,
    language: navigator.language,
    languages: navigator.languages || [],
    platform: navigator.platform,
    cookieEnabled: navigator.cookieEnabled,
    doNotTrack: navigator.doNotTrack,
    onLine: navigator.onLine,
    javaEnabled: typeof navigator.javaEnabled !== 'undefined' ? navigator.javaEnabled() : false,
    pdfViewerEnabled: navigator.pdfViewerEnabled || false,
    webdriver: navigator.webdriver || false
  };
}

// Collect system information
function collectSystemInfo() {
  return {
    screenWidth: screen.width,
    screenHeight: screen.height,
    screenColorDepth: screen.colorDepth,
    screenPixelDepth: screen.pixelDepth,
    availWidth: screen.availWidth,
    availHeight: screen.availHeight,
    innerWidth: window.innerWidth,
    innerHeight: window.innerHeight,
    outerWidth: window.outerWidth,
    outerHeight: window.outerHeight,
    devicePixelRatio: window.devicePixelRatio || 1,
    hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
    maxTouchPoints: navigator.maxTouchPoints || 0,
    deviceMemory: navigator.deviceMemory || 'unknown'
  };
}

// Collect timezone information
function collectTimezoneInfo() {
  const date = new Date();
  return {
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    timezoneOffset: date.getTimezoneOffset(),
    locale: Intl.DateTimeFormat().resolvedOptions().locale,
    currency: Intl.NumberFormat().resolvedOptions().currency || 'unknown',
    dateFormat: Intl.DateTimeFormat().resolvedOptions(),
    timestamp: date.toISOString()
  };
}

// Canvas fingerprinting
function collectCanvasFingerprint() {
  try {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    
    canvas.width = 200;
    canvas.height = 50;
    
    // Draw text with different fonts and colors
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillStyle = '#f60';
    ctx.fillRect(125, 1, 62, 20);
    
    ctx.fillStyle = '#069';
    ctx.fillText('Canvas fingerprint', 2, 15);
    
    ctx.font = '18px Arial';
    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
    ctx.fillText('BrowserFP', 4, 35);
    
    return {
      canvas2D: canvas.toDataURL(),
      canvasHash: hashCanvas(ctx.getImageData(0, 0, canvas.width, canvas.height).data)
    };
  } catch (e) {
    return {
      canvas2D: 'error',
      canvasHash: 'error',
      error: e.message
    };
  }
}

// Simple hash function for canvas data
function hashCanvas(data) {
  let hash = 0;
  for (let i = 0; i < data.length; i++) {
    const char = data[i];
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return hash.toString(16);
}

// WebGL fingerprinting
function collectWebGLFingerprint() {
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    
    if (!gl) {
      return { error: 'WebGL not supported' };
    }
    
    return {
      vendor: gl.getParameter(gl.VENDOR),
      renderer: gl.getParameter(gl.RENDERER),
      version: gl.getParameter(gl.VERSION),
      shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
      maxVertexAttribs: gl.getParameter(gl.MAX_VERTEX_ATTRIBS),
      maxVertexUniformVectors: gl.getParameter(gl.MAX_VERTEX_UNIFORM_VECTORS),
      maxFragmentUniformVectors: gl.getParameter(gl.MAX_FRAGMENT_UNIFORM_VECTORS),
      maxVaryingVectors: gl.getParameter(gl.MAX_VARYING_VECTORS),
      extensions: gl.getSupportedExtensions(),
      unmaskedVendor: getWebGLParameter(gl, 'WEBGL_debug_renderer_info', 'UNMASKED_VENDOR_WEBGL'),
      unmaskedRenderer: getWebGLParameter(gl, 'WEBGL_debug_renderer_info', 'UNMASKED_RENDERER_WEBGL')
    };
  } catch (e) {
    return {
      error: e.message
    };
  }
}

function getWebGLParameter(gl, extension, parameter) {
  try {
    const ext = gl.getExtension(extension);
    return ext ? gl.getParameter(ext[parameter]) : 'unknown';
  } catch (e) {
    return 'unknown';
  }
}

// Audio context fingerprinting
function collectAudioFingerprint() {
  return new Promise((resolve) => {
    try {
      const audioContext = new (window.AudioContext || window.webkitAudioContext)();
      const oscillator = audioContext.createOscillator();
      const analyser = audioContext.createAnalyser();
      const gainNode = audioContext.createGain();
      const scriptProcessor = audioContext.createScriptProcessor(4096, 1, 1);
      
      oscillator.type = 'triangle';
      oscillator.frequency.setValueAtTime(10000, audioContext.currentTime);
      
      gainNode.gain.setValueAtTime(0, audioContext.currentTime);
      oscillator.connect(analyser);
      analyser.connect(scriptProcessor);
      scriptProcessor.connect(gainNode);
      gainNode.connect(audioContext.destination);
      
      scriptProcessor.onaudioprocess = function(bins) {
        const data = bins.inputBuffer.getChannelData(0);
        let fingerprint = 0;
        for (let i = 0; i < data.length; i++) {
          fingerprint += Math.abs(data[i]);
        }
        
        oscillator.disconnect();
        scriptProcessor.disconnect();
        audioContext.close();
        
        resolve({
          audioFingerprint: fingerprint.toString(),
          sampleRate: audioContext.sampleRate,
          maxChannelCount: audioContext.destination.maxChannelCount,
          channelCount: audioContext.destination.channelCount,
          channelCountMode: audioContext.destination.channelCountMode,
          channelInterpretation: audioContext.destination.channelInterpretation,
          state: audioContext.state
        });
      };
      
      oscillator.start(0);
      
      setTimeout(() => {
        resolve({ error: 'Audio fingerprinting timeout' });
      }, 1000);
      
    } catch (e) {
      resolve({
        error: e.message
      });
    }
  });
}

// Font detection
function collectFontFingerprint() {
  const baseFonts = ['monospace', 'sans-serif', 'serif'];
  const testString = 'mmmmmmmmmmlli';
  const testSize = '72px';
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');
  
  // Get baseline measurements
  const baseWidths = baseFonts.map(font => {
    ctx.font = testSize + ' ' + font;
    return ctx.measureText(testString).width;
  });
  
  const testFonts = [
    'Arial', 'Arial Black', 'Arial Narrow', 'Calibri', 'Cambria', 'Comic Sans MS',
    'Courier', 'Courier New', 'Georgia', 'Helvetica', 'Impact', 'Lucida Console',
    'Lucida Sans Unicode', 'Microsoft Sans Serif', 'Palatino', 'Tahoma', 'Times',
    'Times New Roman', 'Trebuchet MS', 'Verdana', 'Geneva', 'Monaco', 'Optima'
  ];
  
  const availableFonts = [];
  
  testFonts.forEach(font => {
    baseFonts.forEach((baseFont, index) => {
      ctx.font = testSize + ' ' + font + ', ' + baseFont;
      const width = ctx.measureText(testString).width;
      
      if (width !== baseWidths[index]) {
        if (!availableFonts.includes(font)) {
          availableFonts.push(font);
        }
      }
    });
  });
  
  return {
    availableFonts: availableFonts,
    fontCount: availableFonts.length,
    baseWidths: baseWidths
  };
}

// Battery API
function collectBatteryInfo() {
  return new Promise((resolve) => {
    if (navigator.getBattery) {
      navigator.getBattery().then(battery => {
        resolve({
          charging: battery.charging,
          level: battery.level,
          chargingTime: battery.chargingTime,
          dischargingTime: battery.dischargingTime
        });
      }).catch(() => {
        resolve({ error: 'Battery API access denied' });
      });
    } else {
      resolve({ error: 'Battery API not supported' });
    }
  });
}

// Collect plugin information
function collectPluginInfo() {
  const plugins = [];
  for (let i = 0; i < navigator.plugins.length; i++) {
    const plugin = navigator.plugins[i];
    plugins.push({
      name: plugin.name,
      description: plugin.description,
      filename: plugin.filename,
      version: plugin.version || 'unknown'
    });
  }
  return {
    plugins: plugins,
    pluginCount: plugins.length
  };
}

// Collect media device information
function collectMediaDevices() {
  return new Promise((resolve) => {
    if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
      navigator.mediaDevices.enumerateDevices().then(devices => {
        const deviceInfo = {
          audioInputs: 0,
          audioOutputs: 0,
          videoInputs: 0,
          devices: []
        };
        
        devices.forEach(device => {
          deviceInfo.devices.push({
            kind: device.kind,
            label: device.label || 'unknown',
            deviceId: device.deviceId ? 'present' : 'none'
          });
          
          if (device.kind === 'audioinput') deviceInfo.audioInputs++;
          else if (device.kind === 'audiooutput') deviceInfo.audioOutputs++;
          else if (device.kind === 'videoinput') deviceInfo.videoInputs++;
        });
        
        resolve(deviceInfo);
      }).catch(() => {
        resolve({ error: 'Media devices access denied' });
      });
    } else {
      resolve({ error: 'Media devices API not supported' });
    }
  });
}

// Display fingerprint data in the UI
function displayFingerprintData() {
  // Server information
  fetch('/api/fingerprint')
    .then(response => response.json())
    .then(serverData => {
      const serverInfo = document.getElementById('server-info');
      serverInfo.innerHTML = '';
      
      Object.entries(serverData.server).forEach(([key, value]) => {
        if (key !== 'allHeaders' && value !== '' && value !== 'unknown') {
          const item = document.createElement('div');
          item.className = 'fingerprint-item';
          item.innerHTML = `
            <span class="fingerprint-label">${formatLabel(key)}:</span>
            <span class="fingerprint-value">${value}</span>
          `;
          serverInfo.appendChild(item);
        }
      });
    })
    .catch(error => {
      console.error('Error fetching server data:', error);
    });
  
  // Browser information
  const browserInfo = document.getElementById('browser-info');
  browserInfo.innerHTML = '';
  
  Object.entries(fingerprintData.browser || {}).forEach(([key, value]) => {
    if (value !== '' && value !== 'unknown') {
      const item = document.createElement('div');
      item.className = 'fingerprint-item';
      item.innerHTML = `
        <span class="fingerprint-label">${formatLabel(key)}:</span>
        <span class="fingerprint-value">${typeof value === 'object' ? JSON.stringify(value) : value}</span>
      `;
      browserInfo.appendChild(item);
    }
  });
  
  // System information
  const systemInfo = document.getElementById('system-info');
  systemInfo.innerHTML = '';
  
  Object.entries(fingerprintData.system || {}).forEach(([key, value]) => {
    if (value !== '' && value !== 'unknown') {
      const item = document.createElement('div');
      item.className = 'fingerprint-item';
      item.innerHTML = `
        <span class="fingerprint-label">${formatLabel(key)}:</span>
        <span class="fingerprint-value">${value}</span>
      `;
      systemInfo.appendChild(item);
    }
  });
  
  // Advanced information
  const advancedInfo = document.getElementById('advanced-info');
  advancedInfo.innerHTML = '';
  
  const advancedData = {
    ...fingerprintData.canvas || {},
    ...fingerprintData.webgl || {},
    ...fingerprintData.audio || {},
    ...fingerprintData.fonts || {},
    ...fingerprintData.battery || {},
    ...fingerprintData.plugins || {},
    ...fingerprintData.media || {},
    ...fingerprintData.timezone || {}
  };
  
  Object.entries(advancedData).forEach(([key, value]) => {
    if (value !== '' && value !== 'unknown' && key !== 'error') {
      const item = document.createElement('div');
      item.className = 'fingerprint-item';
      let displayValue = value;
      
      if (typeof value === 'object' && Array.isArray(value)) {
        displayValue = value.length > 0 ? `${value.length} items` : 'None';
      } else if (typeof value === 'object') {
        displayValue = JSON.stringify(value).substring(0, 100) + (JSON.stringify(value).length > 100 ? '...' : '');
      }
      
      item.innerHTML = `
        <span class="fingerprint-label">${formatLabel(key)}:</span>
        <span class="fingerprint-value">${displayValue}</span>
      `;
      advancedInfo.appendChild(item);
    }
  });
}

// Format label for display
function formatLabel(key) {
  return key
    .replace(/([A-Z])/g, ' $1')
    .replace(/^./, str => str.toUpperCase())
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .replace(/\b\w/g, l => l.toUpperCase());
}

// Generate and display fingerprint hash
async function generateFingerprintHash() {
  const hash = await hashData(fingerprintData);
  const hashElement = document.getElementById('fingerprint-hash');
  hashElement.textContent = hash;
  hashElement.onclick = () => copyHash();
}

// Main fingerprinting function
async function initializeFingerprinting() {
  totalSteps = 10;
  progressValue = 0;
  
  updateProgress(++progressValue, totalSteps, 'Collecting browser info...');
  fingerprintData.browser = collectBrowserInfo();
  
  updateProgress(++progressValue, totalSteps, 'Collecting system info...');
  fingerprintData.system = collectSystemInfo();
  
  updateProgress(++progressValue, totalSteps, 'Collecting timezone info...');
  fingerprintData.timezone = collectTimezoneInfo();
  
  updateProgress(++progressValue, totalSteps, 'Generating canvas fingerprint...');
  fingerprintData.canvas = collectCanvasFingerprint();
  
  updateProgress(++progressValue, totalSteps, 'Collecting WebGL info...');
  fingerprintData.webgl = collectWebGLFingerprint();
  
  updateProgress(++progressValue, totalSteps, 'Detecting fonts...');
  fingerprintData.fonts = collectFontFingerprint();
  
  updateProgress(++progressValue, totalSteps, 'Collecting plugin info...');
  fingerprintData.plugins = collectPluginInfo();
  
  updateProgress(++progressValue, totalSteps, 'Collecting audio fingerprint...');
  fingerprintData.audio = await collectAudioFingerprint();
  
  updateProgress(++progressValue, totalSteps, 'Collecting battery info...');
  fingerprintData.battery = await collectBatteryInfo();
  
  updateProgress(++progressValue, totalSteps, 'Collecting media devices...');
  fingerprintData.media = await collectMediaDevices();
  
  updateProgress(totalSteps, totalSteps, 'Complete!');
  
  // Display all collected data
  displayFingerprintData();
  
  // Generate and display hash
  await generateFingerprintHash();
  
  console.log('Fingerprint data collected:', fingerprintData);
}

// Make initializeFingerprinting globally available
window.initializeFingerprinting = initializeFingerprinting;

// Copy hash function (also make globally available)
window.copyHash = function() {
  const hashElement = document.getElementById('fingerprint-hash');
  const hash = hashElement.textContent.trim();
  
  if (hash && hash !== 'Generating...' && !hash.includes('Generating')) {
    navigator.clipboard.writeText(hash).then(() => {
      const button = document.querySelector('.copy-button');
      const originalText = button.innerHTML;
      button.innerHTML = '<i class="fas fa-check"></i> Copied!';
      setTimeout(() => {
        button.innerHTML = originalText;
      }, 2000);
    });
  }
};

// Auto-initialize when DOM is loaded
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initializeFingerprinting);
} else {
  initializeFingerprinting();
}
