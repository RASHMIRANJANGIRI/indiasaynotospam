// server.js - COMPLETE WORKING VERSION
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';

// Load environment variables FIRST
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('.'));

// Enhanced Spam Detection with Advanced Link Analysis
class EnhancedSpamDetector {
  constructor() {
    this.geminiApiKey = process.env.GEMINI_API_KEY;
    this.useGemini = !!this.geminiApiKey && this.geminiApiKey.length > 30;
    
    // Known malicious domains and patterns
    this.suspiciousDomains = [
      'bit.ly', 'tinyurl.com', 'shorturl.at', 'cutt.ly', 'is.gd', 'cli.gs',
      'bc.vc', 'adf.ly', 'sh.st', 'goo.gl', 'ow.ly', 't.co', 'rb.gy',
      'bank-secure.com', 'verify-account.com', 'payment-update.com',
      'amazon-security.com', 'microsoft-support.com', 'apple-verify.com',
      'paypal-confirm.com', 'netflix-billing.com', 'google-security.com'
    ];
    
    this.suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club'];
    
    console.log(`🧠 Gemini AI: ${this.useGemini ? 'ENABLED' : 'DISABLED - Using Advanced Rule-Based System'}`);
  }

  // ==================== ADVANCED LINK DETECTION ====================
  analyzeLinks(content) {
    const linkAnalysis = {
      totalUrls: 0,
      suspiciousUrls: [],
      suspiciousDomains: [],
      shorteners: [],
      reasons: []
    };

    // Extract all URLs
    const urlRegex = /(https?:\/\/[^\s]+|www\.[^\s]+|\.[a-z]{2,}\/[^\s]*)/gi;
    const urls = content.match(urlRegex) || [];
    linkAnalysis.totalUrls = urls.length;

    if (urls.length === 0) {
      return linkAnalysis;
    }

    // Analyze each URL
    urls.forEach(url => {
      const lowerUrl = url.toLowerCase();
      
      // Check for URL shorteners
      if (this.isUrlShortener(lowerUrl)) {
        linkAnalysis.shorteners.push(url);
        linkAnalysis.reasons.push(`URL shortener detected: ${this.extractDomain(url)}`);
      }
      
      // Check for suspicious domains
      if (this.isSuspiciousDomain(lowerUrl)) {
        linkAnalysis.suspiciousDomains.push(url);
        linkAnalysis.reasons.push(`Suspicious domain: ${this.extractDomain(url)}`);
      }
      
      // Check for suspicious TLDs
      if (this.hasSuspiciousTld(lowerUrl)) {
        linkAnalysis.suspiciousUrls.push(url);
        linkAnalysis.reasons.push(`Suspicious TLD in URL: ${this.extractTld(url)}`);
      }
      
      // Check for IP addresses (often used in phishing)
      if (this.containsIpAddress(url)) {
        linkAnalysis.suspiciousUrls.push(url);
        linkAnalysis.reasons.push(`IP address in URL (often phishing): ${url}`);
      }
      
      // Check for @ symbols (obfuscation technique)
      if (url.includes('@')) {
        linkAnalysis.suspiciousUrls.push(url);
        linkAnalysis.reasons.push(`URL contains @ symbol (obfuscation attempt): ${url}`);
      }
    });

    // All URLs are suspicious if any red flags found
    linkAnalysis.suspiciousUrls = [...new Set([...linkAnalysis.suspiciousUrls, ...linkAnalysis.shorteners, ...linkAnalysis.suspiciousDomains])];
    
    return linkAnalysis;
  }

  isUrlShortener(url) {
    const shorteners = [
      'bit.ly', 'tinyurl.com', 'shorturl.at', 'cutt.ly', 'is.gd', 'cli.gs',
      'bc.vc', 'adf.ly', 'sh.st', 'goo.gl', 'ow.ly', 't.co', 'rb.gy',
      'buff.ly', 'git.io', 'mcaf.ee', 'su.pr', 'tr.im', 'v.gd', 'x.co'
    ];
    return shorteners.some(shortener => url.includes(shortener));
  }

  isSuspiciousDomain(url) {
    return this.suspiciousDomains.some(domain => url.includes(domain));
  }

  hasSuspiciousTld(url) {
    return this.suspiciousTlds.some(tld => url.includes(tld));
  }

  containsIpAddress(url) {
    const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
    return ipRegex.test(url);
  }

  extractDomain(url) {
    try {
      const domain = url.match(/https?:\/\/([^\/]+)/);
      return domain ? domain[1] : url;
    } catch {
      return url;
    }
  }

  extractTld(url) {
    const tldMatch = url.match(/\.([a-z]{2,})($|\/)/);
    return tldMatch ? tldMatch[1] : 'unknown';
  }

  // ==================== GEMINI AI ANALYSIS ====================
  async analyzeWithGemini(prompt) {
    if (!this.useGemini) {
      throw new Error('Gemini AI disabled');
    }

    try {
      console.log('🤖 Sending request to Gemini API...');
      
      const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=${this.geminiApiKey}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          contents: [{
            parts: [{
              text: prompt
            }]
          }],
          generationConfig: {
            temperature: 0.1,
            topK: 40,
            topP: 0.95,
            maxOutputTokens: 1024,
          }
        })
      });

      if (!response.ok) {
        throw new Error(`Gemini API error: ${response.status}`);
      }

      const data = await response.json();
      const geminiResponse = data.candidates[0].content.parts[0].text;
      
      return this.parseGeminiResponse(geminiResponse);
      
    } catch (error) {
      console.error('❌ Gemini AI failed:', error.message);
      throw error;
    }
  }

  parseGeminiResponse(response) {
    try {
      const jsonMatch = response.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        return JSON.parse(jsonMatch[0]);
      }
      throw new Error('No JSON found in response');
    } catch (error) {
      console.error('Failed to parse Gemini response:', error);
      return {
        isSpam: false,
        confidence: "Low",
        spamScore: 0,
        category: "analysis_failed",
        riskLevel: "Minimal",
        contentAnalysis: ["AI analysis failed"],
        senderAnalysis: ["Please try again"],
        recommendation: "AI analysis unavailable. Please verify manually.",
        aiInsights: "Gemini AI parsing failed"
      };
    }
  }

  // ==================== ENHANCED RULE-BASED ANALYSIS ====================
  advancedRuleAnalysis(content, senderInfo, type) {
    console.log(`🛡️ Using Advanced Rule-Based Analysis for ${type}`);
    
    let spamScore = 0;
    const contentAnalysis = [];
    const senderAnalysis = [];
    
    const lowerContent = content.toLowerCase();
    const lowerSender = senderInfo.identifier ? senderInfo.identifier.toLowerCase() : '';

    // === ADVANCED LINK ANALYSIS ===
    const linkAnalysis = this.analyzeLinks(content);
    
    if (linkAnalysis.totalUrls > 0) {
      // Base score for having URLs
      spamScore += linkAnalysis.totalUrls * 3;
      contentAnalysis.push(`Found ${linkAnalysis.totalUrls} URLs in message`);
      
      // URL shorteners are high risk
      if (linkAnalysis.shorteners.length > 0) {
        spamScore += linkAnalysis.shorteners.length * 8;
        contentAnalysis.push(`⚠️ ${linkAnalysis.shorteners.length} URL shortener(s) detected: ${linkAnalysis.shorteners.map(url => this.extractDomain(url)).join(', ')}`);
      }
      
      // Suspicious domains
      if (linkAnalysis.suspiciousDomains.length > 0) {
        spamScore += linkAnalysis.suspiciousDomains.length * 10;
        contentAnalysis.push(`🚨 ${linkAnalysis.suspiciousDomains.length} known suspicious domain(s): ${linkAnalysis.suspiciousDomains.map(url => this.extractDomain(url)).join(', ')}`);
      }
      
      // Suspicious TLDs
      if (linkAnalysis.suspiciousUrls.length > 0) {
        spamScore += linkAnalysis.suspiciousUrls.length * 6;
        contentAnalysis.push(`⚠️ ${linkAnalysis.suspiciousUrls.length} URL(s) with suspicious TLDs`);
      }
      
      // Add all link analysis reasons
      linkAnalysis.reasons.forEach(reason => {
        contentAnalysis.push(reason);
      });
    }

    // === CONTENT ANALYSIS ===
    
    // Financial scams
    const financialKeywords = ['win', 'won', 'prize', 'cash', 'money', 'million', 'lottery', 'jackpot', 'reward', 'claim'];
    const financialMatches = financialKeywords.filter(word => lowerContent.includes(word));
    if (financialMatches.length > 0) {
      spamScore += financialMatches.length * 5;
      contentAnalysis.push(`Financial scam keywords: ${financialMatches.join(', ')}`);
    }

    // Urgency tactics
    const urgencyKeywords = ['urgent', 'immediately', 'act now', 'last chance', 'final notice', 'suspended', 'verify now'];
    const urgencyMatches = urgencyKeywords.filter(word => lowerContent.includes(word));
    if (urgencyMatches.length > 0) {
      spamScore += urgencyMatches.length * 4;
      contentAnalysis.push(`Urgency pressure: ${urgencyMatches.join(', ')}`);
    }

    // Banking phishing
    const bankingKeywords = ['bank', 'account', 'password', 'credit card', 'debit card', 'ssn', 'login', 'verify'];
    const bankingMatches = bankingKeywords.filter(word => lowerContent.includes(word));
    if (bankingMatches.length > 0) {
      spamScore += bankingMatches.length * 6;
      contentAnalysis.push(`Banking/phishing terms: ${bankingMatches.join(', ')}`);
    }

    // Free offers
    const freeKeywords = ['free', 'gift', 'bonus', 'no cost', 'special offer', 'discount', 'coupon'];
    const freeMatches = freeKeywords.filter(word => lowerContent.includes(word));
    if (freeMatches.length > 0) {
      spamScore += freeMatches.length * 3;
      contentAnalysis.push(`Free offers: ${freeMatches.join(', ')}`);
    }

    // Excessive capitalization
    const upperCaseRatio = (content.match(/[A-Z]/g) || []).length / content.length;
    if (upperCaseRatio > 0.4) {
      spamScore += 15;
      contentAnalysis.push(`Excessive capitalization (${Math.round(upperCaseRatio * 100)}% uppercase)`);
    }

    // Exclamation marks
    const exclamationCount = (content.match(/!/g) || []).length;
    if (exclamationCount > 2) {
      spamScore += exclamationCount * 2;
      contentAnalysis.push(`Excessive exclamation marks (${exclamationCount})`);
    }

    // === SENDER ANALYSIS ===
    
    if (senderInfo.identifier) {
      // Phone number analysis (WhatsApp)
      if (type === 'whatsapp') {
        const phone = senderInfo.identifier.replace(/[\s\-\(\)]/g, '');
        
        // Premium rate numbers
        if (/^\+1-900-|^\+44-90|^\+49-900/.test(phone)) {
          spamScore += 20;
          senderAnalysis.push('Premium rate phone number detected');
        }
        
        // Virtual numbers
        if (/^\+1-800-|^\+1-888-|^\+1-877-|^\+1-866-/.test(phone)) {
          spamScore += 10;
          senderAnalysis.push('Virtual/toll-free number detected');
        }
        
        // International numbers (high risk)
        if (phone.startsWith('+') && !phone.startsWith('+1')) {
          spamScore += 8;
          senderAnalysis.push('International number - higher risk');
        }
      }

      // Email analysis (Gmail)
      if (type === 'email') {
        const email = senderInfo.identifier.toLowerCase();
        
        // Disposable emails
        if (/@temp-mail|@guerrillamail|@10minutemail|@throwawaymail/.test(email)) {
          spamScore += 25;
          senderAnalysis.push('Disposable/temporary email detected');
        }
        
        // Suspicious domains
        if (/@.*\.tk$|@.*\.ml$|@.*\.ga$|@.*\.cf$/.test(email)) {
          spamScore += 20;
          senderAnalysis.push('Suspicious email domain');
        }
        
        // Free email providers
        if (/@gmail\.com$|@yahoo\.com$|@hotmail\.com$/.test(email)) {
          spamScore += 5;
          senderAnalysis.push('Free email provider - moderate risk');
        }
      }

      // SMS Sender ID analysis
      if (type === 'sms') {
        const senderId = senderInfo.identifier.toUpperCase();
        
        // Brand impersonation
        if (/BANK|PAYMENT|CREDIT|AMAZON|NETFLIX|PAYPAL|MICROSOFT|APPLE|GOOGLE/.test(senderId)) {
          spamScore += 15;
          senderAnalysis.push('Possible brand impersonation in sender ID');
        }
        
        // Marketing IDs
        if (/PROMO|OFFER|DEAL|SALE|DISCOUNT|COUPON/.test(senderId)) {
          spamScore += 10;
          senderAnalysis.push('Marketing/promotional sender ID');
        }
        
        // Urgency in sender ID
        if (/URGENT|ALERT|IMPORTANT|NOTICE/.test(senderId)) {
          spamScore += 12;
          senderAnalysis.push('Urgency indicators in sender ID');
        }
      }
    }

    // === FINAL CALCULATION ===
    const isSpam = spamScore > 25;
    let confidence = 'Low';
    let riskLevel = 'Minimal';
    
    if (spamScore > 60) {
      confidence = 'Very High';
      riskLevel = 'Critical';
    } else if (spamScore > 45) {
      confidence = 'High';
      riskLevel = 'High';
    } else if (spamScore > 30) {
      confidence = 'Medium';
      riskLevel = 'Medium';
    } else if (spamScore > 15) {
      riskLevel = 'Low';
    }

    let category = 'legitimate';
    if (spamScore > 40) {
      if (contentAnalysis.some(r => r.includes('bank'))) category = 'phishing';
      else if (contentAnalysis.some(r => r.includes('win'))) category = 'financial_scam';
      else if (contentAnalysis.some(r => r.includes('free'))) category = 'promotional';
      else category = 'suspicious';
    }

    const recommendation = this.generateRecommendation(isSpam, spamScore, type, contentAnalysis, linkAnalysis);
    const aiInsights = this.useGemini ? 
      "AI analysis unavailable - using advanced rule-based detection" : 
      "Advanced rule-based spam detection with enhanced link analysis";

    return {
      isSpam,
      confidence,
      spamScore: Math.min(spamScore, 100),
      category,
      riskLevel,
      contentAnalysis: contentAnalysis.length > 0 ? contentAnalysis : ['No strong spam indicators in content'],
      senderAnalysis: senderAnalysis.length > 0 ? senderAnalysis : ['No strong sender red flags'],
      linkAnalysis,
      recommendation,
      aiInsights
    };
  }

  generateRecommendation(isSpam, score, type, contentAnalysis, linkAnalysis) {
    let linkWarning = '';
    
    if (linkAnalysis.totalUrls > 0) {
      if (linkAnalysis.suspiciousDomains.length > 0) {
        linkWarning = ` 🚨 CONTAINS KNOWN SUSPICIOUS DOMAINS!`;
      } else if (linkAnalysis.shorteners.length > 0) {
        linkWarning = ` ⚠️ CONTAINS URL SHORTENERS (high risk)!`;
      } else if (linkAnalysis.suspiciousUrls.length > 0) {
        linkWarning = ` ⚠️ CONTAINS SUSPICIOUS LINKS!`;
      } else {
        linkWarning = ` Contains ${linkAnalysis.totalUrls} URL(s) - be cautious.`;
      }
    }

    if (!isSpam) {
      if (score > 15) {
        return `⚠️ Some suspicious elements detected.${linkWarning} Proceed with caution and verify the sender.`;
      }
      return `✅ This message appears legitimate.${linkWarning} Always be cautious with unknown senders.`;
    }

    if (score > 60) {
      return `🚫 CRITICAL: High-confidence spam detected.${linkWarning} DO NOT click links, share information, or respond. ${type === 'whatsapp' ? 'Block this number.' : type === 'email' ? 'Mark as spam and delete.' : 'Delete immediately.'}`;
    }

    if (score > 40) {
      return `⚠️ HIGH RISK: Strong spam indicators detected.${linkWarning} Avoid interaction and ${type === 'whatsapp' ? 'consider blocking' : 'delete this message'}.`;
    }

    return `⚠️ CAUTION: Spam characteristics detected.${linkWarning} Verify sender identity before responding.`;
  }

  // ==================== PLATFORM-SPECIFIC ANALYSIS ====================
  async analyzeWhatsApp(message, phoneNumber) {
    const senderInfo = {
      type: 'Phone Number',
      identifier: phoneNumber || 'Not provided'
    };

    // Try Gemini first if available
    if (this.useGemini) {
      try {
        const prompt = `
          Analyze this WhatsApp message for spam. Phone: ${phoneNumber}. Message: "${message}"
          Respond with JSON: {"isSpam":boolean, "confidence":"High/Medium/Low", "spamScore":0-100, "category":"string", "riskLevel":"Critical/High/Medium/Low", "contentAnalysis":["array"], "senderAnalysis":["array"], "recommendation":"string", "aiInsights":"string"}
        `;
        
        const aiResult = await this.analyzeWithGemini(prompt);
        return this.formatResult(aiResult, 'WhatsApp', senderInfo, 'Google Gemini AI');
      } catch (error) {
        console.log('🔄 Gemini failed, using rule-based analysis for WhatsApp');
      }
    }

    // Use rule-based analysis
    const ruleResult = this.advancedRuleAnalysis(message, senderInfo, 'whatsapp');
    return this.formatResult(ruleResult, 'WhatsApp', senderInfo, 'Advanced Rule-Based System');
  }

  async analyzeGmail(message, senderEmail, subject = '') {
    const senderInfo = {
      type: 'Email Address',
      identifier: senderEmail || 'Not provided',
      subject: subject || 'No Subject'
    };

    if (this.useGemini) {
      try {
        const prompt = `
          Analyze this email for spam. Sender: ${senderEmail}. Subject: "${subject}". Message: "${message}"
          Respond with JSON: {"isSpam":boolean, "confidence":"High/Medium/Low", "spamScore":0-100, "category":"string", "riskLevel":"Critical/High/Medium/Low", "contentAnalysis":["array"], "senderAnalysis":["array"], "recommendation":"string", "aiInsights":"string"}
        `;
        
        const aiResult = await this.analyzeWithGemini(prompt);
        return this.formatResult(aiResult, 'Email', senderInfo, 'Google Gemini AI');
      } catch (error) {
        console.log('🔄 Gemini failed, using rule-based analysis for Email');
      }
    }

    const ruleResult = this.advancedRuleAnalysis(message, senderInfo, 'email');
    return this.formatResult(ruleResult, 'Email', senderInfo, 'Advanced Rule-Based System');
  }

  async analyzeSMS(message, senderID) {
    const senderInfo = {
      type: 'Sender ID', 
      identifier: senderID || 'Not provided'
    };

    if (this.useGemini) {
      try {
        const prompt = `
          Analyze this SMS for spam. Sender ID: ${senderID}. Message: "${message}"
          Respond with JSON: {"isSpam":boolean, "confidence":"High/Medium/Low", "spamScore":0-100, "category":"string", "riskLevel":"Critical/High/Medium/Low", "contentAnalysis":["array"], "senderAnalysis":["array"], "recommendation":"string", "aiInsights":"string"}
        `;
        
        const aiResult = await this.analyzeWithGemini(prompt);
        return this.formatResult(aiResult, 'SMS', senderInfo, 'Google Gemini AI');
      } catch (error) {
        console.log('🔄 Gemini failed, using rule-based analysis for SMS');
      }
    }

    const ruleResult = this.advancedRuleAnalysis(message, senderInfo, 'sms');
    return this.formatResult(ruleResult, 'SMS', senderInfo, 'Advanced Rule-Based System');
  }

  formatResult(analysisResult, platform, senderInfo, engine) {
    return {
      ...analysisResult,
      platform,
      analyzedAt: new Date().toISOString(),
      analysisEngine: engine,
      senderInfo
    };
  }
}

// Initialize detector
const spamDetector = new EnhancedSpamDetector();

// ==================== API ROUTES ====================
app.post("/api/check/whatsapp", async (req, res) => {
  try {
    const { phoneNumber, message } = req.body;

    if (!message?.trim()) {
      return res.json({ 
        success: false, 
        error: "WhatsApp message content is required" 
      });
    }

    console.log(`📱 Analyzing WhatsApp: ${phoneNumber}`);
    
    const result = await spamDetector.analyzeWhatsApp(message, phoneNumber);
    
    res.json({ 
      success: true, 
      result
    });
  } catch (error) {
    console.error("WhatsApp analysis error:", error);
    res.json({ 
      success: false, 
      error: error.message 
    });
  }
});

app.post("/api/check/gmail", async (req, res) => {
  try {
    const { sender, message, subject } = req.body;

    if (!message?.trim()) {
      return res.json({ 
        success: false, 
        error: "Email content is required" 
      });
    }

    console.log(`📧 Analyzing Email: ${sender}`);
    
    const result = await spamDetector.analyzeGmail(message, sender, subject);
    
    res.json({ 
      success: true, 
      result
    });
  } catch (error) {
    console.error("Email analysis error:", error);
    res.json({ 
      success: false, 
      error: error.message 
    });
  }
});

app.post("/api/check/sms", async (req, res) => {
  try {
    const { sender, message } = req.body;

    if (!message?.trim()) {
      return res.json({ 
        success: false, 
        error: "SMS content is required" 
      });
    }

    console.log(`💬 Analyzing SMS: ${sender}`);
    
    const result = await spamDetector.analyzeSMS(message, sender);
    
    res.json({ 
      success: true, 
      result
    });
  } catch (error) {
    console.error("SMS analysis error:", error);
    res.json({ 
      success: false, 
      error: error.message 
    });
  }
});

// Health check
app.get("/api/health", (req, res) => {
  res.json({ 
    status: "OK", 
    service: "SayNoToSpam",
    timestamp: new Date().toISOString(),
    gemini: {
      enabled: spamDetector.useGemini,
      status: spamDetector.useGemini ? "Active" : "Using Rule-Based System"
    },
    features: [
      "WhatsApp: Message + Phone Number Analysis",
      "Gmail: Message + Email Address Analysis", 
      "SMS: Message + Sender ID Analysis",
      "Advanced Link Detection",
      "Real-time Security Assessment"
    ]
  });
});

// Serve HTML for all routes
app.get("*", (req, res) => {
  res.sendFile(process.cwd() + "/index.html");
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 SayNoToSpam AI running on http://localhost:${PORT}`);
  console.log(`📱 WhatsApp: Message + Phone analysis`);
  console.log(`📧 Gmail: Message + Email analysis`); 
  console.log(`💬 SMS: Message + Sender ID analysis`);
  console.log(`🛡️  Protection: ${spamDetector.useGemini ? 'Gemini AI + Rule-Based' : 'Advanced Rule-Based'}`);
  console.log(`🔗 Advanced link detection: ENABLED`);
});